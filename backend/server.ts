import {engineCapabilities, projectEngine} from './engine/capabilities.ts';
import {nativeBinary, nativeAvailable as rustAvailable, nativeQuery} from './engine/native.ts';
import { createServer } from 'node:http';
import { readListing, readListingFunctions } from './listing.ts';
import { readFile, writeFile, mkdir, readdir, rename, access, rm } from 'node:fs/promises';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID, createHash } from 'node:crypto';
import { spawn, type ChildProcess } from 'node:child_process';
import { constants, existsSync } from 'node:fs';
import type { Project, Analysis, FunctionInfo } from './types.ts';
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DATA = process.env.DATA_DIR || join(ROOT, 'data');
await mkdir(DATA, { recursive: true });
const port = Number(process.env.PORT || 4310), host = `127.0.0.1:${port}`;
const projects = new Map<string, Project>();
const preparing = new Set<string>();
const edits = new Set<string>();
let internalJob: {id:string;child:ChildProcess}|undefined;
let settings: {engine:'ghidra'|'internal'}={engine:'internal'};
try {const saved=JSON.parse(await readFile(join(DATA,'settings.json'),'utf8'));if(['ghidra','internal'].includes(saved.engine))settings=saved;} catch(e) {if((e as NodeJS.ErrnoException).code!=='ENOENT')console.error('Configuración inválida: se usará el motor interno.');}
let settingsWrite=Promise.resolve();
let decompiling = false;
const pendingDecompiles = new Map<string, Promise<FunctionInfo>>();
let active: {
    id: string;
    child: ChildProcess;
} | undefined;
const runtime = await readdir(join(ROOT, '.runtime')).catch(() => [] as string[]);
const ghidra = process.env.GHIDRA_HOME || join(ROOT, '.runtime', runtime.find(x => x.startsWith('ghidra_') && !x.endsWith('.zip')) || 'missing');
const javaHome = process.env.JAVA_HOME || join(ROOT, '.runtime', runtime.find(x => x.startsWith('jdk-')) || 'missing', 'Contents', 'Home');
const launcher = join(ghidra, 'support', 'analyzeHeadless');
const platform = `${process.platform === 'darwin' ? 'mac' : 'linux'}_${process.arch === 'arm64' ? 'arm' : 'x86'}_64`;
const nativePaths = ['os', 'build/os'].map(folder => join(ghidra, 'Ghidra', 'Features', 'Decompiler', folder, platform, 'decompile'));
const nativeAvailable = await Promise.any(nativePaths.map(path => access(path, constants.X_OK))).then(() => true, () => false);
const available = nativeAvailable && await Promise.all([access(launcher, constants.X_OK), access(join(javaHome, 'bin', 'java'), constants.X_OK)]).then(() => true, () => false);
const writes = new Map<string, Promise<void>>();
async function save(p: Project) { const content = JSON.stringify(p); const task = (writes.get(p.id) || Promise.resolve()).catch(() => { }).then(async () => { const path = join(DATA, p.id, 'project.json'); await writeFile(path + '.tmp', content); await rename(path + '.tmp', path); }); writes.set(p.id, task); await task; }
for (const id of await readdir(DATA)) {
    if (!/^[a-f0-9-]{36}$/.test(id))
        continue;
    try {
        const p: Project = JSON.parse(await readFile(join(DATA, id, 'project.json'), 'utf8'));
        if (p.status === 'analyzing' || p.status === 'queued') {
            p.status = 'failed';
            p.error = 'El servidor se interrumpió. Importa el archivo de nuevo.';
            await save(p);
        }
        projects.set(id, p);
    }
    catch { }
}
function runNext() {
    if (active || decompiling || internalJob)
        return;
    const p = [...projects.values()].find(p => p.status === 'queued' && !preparing.has(p.id));
    if (!p)
        return;
    if(p.engine==='internal'){void runInternal(p);return;}
    if(!available){p.status='failed';p.error='Ghidra no está disponible. Selecciona el motor interno para un proyecto compatible.';void save(p).then(runNext);return;}
    p.status = 'analyzing';
    p.log = 'Iniciando análisis estático de Ghidra…\n';
    void save(p);
    const dir = join(DATA, p.id);
    const editing = edits.has(p.id);
    const reuse = p.persistent && existsSync(join(dir,'analysis.gpr'));
    const args = [dir, 'analysis', ...(reuse ? ['-process','input.bin'] : ['-overwrite','-import',join(dir,'input.bin')]), '-scriptPath',join(ROOT,'scripts')];
    if(editing) args.push('-noanalysis','-preScript','MutateWeb.java',join(dir,'edit.json'),join(dir,'edit-receipt.json'));
    args.push('-postScript','ExportWeb.java',join(dir,'result.json'),'-postScript','ExportListing.java',dir,'-analysisTimeoutPerFile','300','-max-cpu','2');
    const child = spawn(launcher, args, { env: { ...process.env, JAVA_HOME: javaHome, JAVA_HOME_OVERRIDE: javaHome, GHIDRA_HEADLESS_MAXMEM: '2G', JAVA_TOOL_OPTIONS: `-Dapplication.settingsdir="${join(DATA, 'settings')}" -Dapplication.cachedir="${join(DATA, 'cache')}" -Djava.io.tmpdir="${dir}"` }, detached: process.platform !== 'win32' });
    active = { id: p.id, child };
    let finished = false;
    const append = (data: Buffer) => { p.log = (p.log + data.toString()).slice(-24000); };
    child.stdout?.on('data', append);
    child.stderr?.on('data', append);
    const timer = setTimeout(() => { p.error = 'Se alcanzó el límite total de 10 minutos.'; kill(child); }, 600000);
    async function finish(error?: string) { if (finished)
        return; finished = true; clearTimeout(timer); if (p!.status !== 'cancelled') {
        try {
            if (error || p!.error)
                throw Error(error || p!.error);
            const snapshot = JSON.parse(await readFile(join(dir, 'result.json'), 'utf8'));
            if(!snapshot.listingGeneration) throw new Error('No se generó el listing completo. Consulta el registro.');
            p!.status = 'ready';
            p!.persistent = true;
            if(editing) {
                const receipt=JSON.parse(await readFile(join(dir,'edit-receipt.json'),'utf8'));
                if(!receipt.ok) p!.error='Cambio rechazado por Ghidra: '+receipt.error;
            }
        }
        catch (e) {
            p!.status = 'failed';
            p!.error = String(e);
        }
    } edits.delete(p!.id); await save(p!); active = undefined; runNext(); }
    child.on('error', e => void finish(e.message));
    child.on('close', code => void finish(code === 0 ? undefined : `Ghidra terminó con código ${code}. Consulta el registro.`));
}
async function runInternal(p:Project){
    const dir=join(DATA,p.id), editing=edits.has(p.id);
    p.status='analyzing';p.log='Motor interno Rust: análisis estático independiente.\n';
    // Reserve before awaiting I/O, so requests cannot start a second job.
    const child=spawn(nativeBinary,[editing?'edit':'analyze',dir,p.name],{stdio:['ignore','pipe','pipe']});
    internalJob={id:p.id,child};
    void save(p);
    let finished=false, failure='';
    const append=(data:Buffer)=>{const text=data.toString();p.log=(p.log+text).slice(-24000);for(const line of text.split('\n')){try{const event=JSON.parse(line);if(event.event==='error')failure=event.error;}catch{}}};
    child.stdout?.on('data',append);child.stderr?.on('data',append);
    const timer=setTimeout(()=>{failure='El motor interno superó dos minutos.';child.kill('SIGKILL');},125000);
    async function finish(error?:string){
        if(finished)return;finished=true;clearTimeout(timer);
        if(p.status!=='cancelled'){
            try {
                if(error)throw Error(error);
                const result=JSON.parse(await readFile(join(dir,'result.json'),'utf8'));
                if(result.nativeEngine!=='rust'||!result.listingGeneration)throw Error('Resultado nativo incompleto');
                p.status='ready';p.persistent=true;delete p.error;
            }catch(e){p.status=p.persistent&&existsSync(join(dir,'result.json'))?'ready':'failed';p.error=String(e);}
        }
        edits.delete(p.id);
        try{await save(p);}finally{internalJob=undefined;runNext();}
    }
    child.on('error',e=>void finish(e.message+' · Ejecuta npm run engine:build.'));
    child.on('close',code=>void finish(code===0?undefined:failure||'El motor Rust terminó con código '+code));
}
async function decompile(id: string, generation: string, address: string): Promise<FunctionInfo> {
    const key = `${id}/${generation}/${address}`;
    const pending = pendingDecompiles.get(key);
    if (pending) return pending;
    if (active || decompiling || internalJob) throw Object.assign(Error('Motor ocupado. Vuelve a intentar cuando termine.'), {status:409});
    decompiling = true;
    const task = (async () => {
        const dir = join(DATA,id), output = join(dir,generation,`function-${createHash('sha256').update(address).digest('hex')}.json`);
        try { return JSON.parse(await readFile(output,'utf8')) as FunctionInfo; }
        catch(e) { if((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e; }
        const args = [dir,'analysis','-process','input.bin','-readOnly','-noanalysis','-scriptPath',join(ROOT,'scripts'),'-postScript','ExportWeb.java',output,address,'-max-cpu','2'];
        await new Promise<void>((resolve,reject) => {
            const child = spawn(launcher,args,{env:{...process.env,JAVA_HOME:javaHome,JAVA_HOME_OVERRIDE:javaHome,GHIDRA_HEADLESS_MAXMEM:'2G',JAVA_TOOL_OPTIONS:`-Dapplication.settingsdir="${join(DATA,'settings')}" -Dapplication.cachedir="${join(DATA,'cache')}" -Djava.io.tmpdir="${dir}"`},detached:process.platform!=='win32'});
            active={id,child};
            let log='', expired=false;
            const append=(b:Buffer)=>{log=(log+b.toString()).slice(-4000);};
            child.stdout?.on('data',append);child.stderr?.on('data',append);
            const timer=setTimeout(()=>{expired=true;kill(child);},120000);
            child.on('error',e=>{clearTimeout(timer);reject(e);});
            child.on('close',code=>{clearTimeout(timer);if(code===0&&!expired)resolve();else reject(Error(expired?'La decompilación superó dos minutos.':`Ghidra no pudo decompilar: ${log}`));});
        });
        return JSON.parse(await readFile(output,'utf8')) as FunctionInfo;
    })();
    pendingDecompiles.set(key,task);
    try { return await task; }
    finally { pendingDecompiles.delete(key);decompiling=false;active=undefined;runNext(); }
}
function kill(child: ChildProcess) { try {
    if (child.pid)
        process.kill(process.platform === 'win32' ? child.pid : -child.pid, 'SIGTERM');
}
catch { } }
async function body(req: import('node:http').IncomingMessage, max: number) { let size = 0; const chunks: Buffer[] = []; for await (const chunk of req) {
    size += chunk.length;
    if (size > max)
        throw Object.assign(Error('Archivo demasiado grande. Máximo 32 MiB.'), { status: 413 });
    chunks.push(chunk);
} return Buffer.concat(chunks); }
const server = createServer(async (req, res) => {
    const json = (code: number, value: unknown) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(value)); };
    try {
        if (req.headers.host !== host && req.headers.host !== `localhost:${port}`)
            return json(403, { error: 'Host no permitido' });
        if (req.headers.origin && !['http://' + host, `http://localhost:${port}`].includes(req.headers.origin))
            return json(403, { error: 'Origen no permitido' });
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'");
        const url = new URL(req.url || '/', 'http://' + host), path = url.pathname;
        if (path === '/api/health')
            return json(200, { engine: (settings.engine==='internal'?rustAvailable():available) ? 'ready' : 'missing', selectedEngine:settings.engine, ghidraAvailable:available, message:settings.engine==='internal'?'Motor interno Rust · ARM64 / x86-64':available?'Ghidra disponible':'Ghidra no está disponible', busy: !!active||!!internalJob });
        if(path==='/api/engines'&&req.method==='GET')return json(200,['internal','ghidra'].map(engine=>engineCapabilities(engine as 'internal'|'ghidra',available,undefined,rustAvailable())));
        if(path==='/api/settings'&&req.method==='GET')return json(200,{...settings,ghidraAvailable:available});
        if(path==='/api/settings'&&req.method==='PUT'){
            const value=JSON.parse((await body(req,1000)).toString());
            if(!value||!['ghidra','internal'].includes(value.engine))return json(400,{error:'Motor inválido'});
            const next={engine:value.engine} as typeof settings;
            const update=settingsWrite.catch(()=>{}).then(async()=>{await writeFile(join(DATA,'settings.json.tmp'),JSON.stringify(next));await rename(join(DATA,'settings.json.tmp'),join(DATA,'settings.json'));settings=next;});
            settingsWrite=update;await update;return json(200,settings);
        }
        if (path === '/api/projects' && req.method === 'GET')
            return json(200, [...projects.values()].map(({ log, ...p }) => p).reverse());
        if (path === '/api/projects' && req.method === 'POST') {
            const engine=url.searchParams.get('engine')||settings.engine;
            if(!['ghidra','internal'].includes(engine))return json(400,{error:'Motor inválido'});
            if (engine==='ghidra'&&!available)
                return json(503, { error: 'El motor Ghidra no está disponible. Consulta README.md.' });
            if ([...projects.values()].filter(p => ['queued', 'analyzing'].includes(p.status)).length >= 3)
                return json(429, { error: 'Hay tres análisis pendientes. Espera a que terminen.' });
            const buffer = await body(req, 32 * 1024 * 1024);
            if (!buffer.length)
                return json(400, { error: 'Archivo vacío' });
            const id = randomUUID();
            const p: Project = { engine:engine as 'ghidra'|'internal', id, name: (url.searchParams.get('name') || 'binary').slice(0, 200), created: new Date().toISOString(), status: 'queued', log: '', size: buffer.length, sha256: createHash('sha256').update(buffer).digest('hex'), annotations: {} };
            await mkdir(join(DATA, id));
            await writeFile(join(DATA, id, 'input.bin'), buffer);
            await save(p);
            projects.set(id, p);
            runNext();
            return json(202, p);
        }
        const match = path.match(/^\/api\/projects\/([a-f0-9-]{36})(?:\/(result|annotations|cancel|bytes|reanalyze|edit|byte-search|listing|listing-functions|decompile|capabilities|program|native-search|native-function|native-indirect))?$/);
        if (match) {
            const p = projects.get(match[1]);
            if (!p)
                return json(404, { error: 'Proyecto no encontrado' });
            const action = match[2];
            const capabilities=engineCapabilities(projectEngine(p),available,p,rustAvailable());
            if(req.method==='GET'&&action==='capabilities')return json(200,capabilities);
            if(req.method==='GET'&&action==='program'){
                if(projectEngine(p)!=='internal')return json(422,{error:'El modelo central todavía no se exporta desde el adaptador Ghidra.'});
                if(p.status!=='ready')return json(409,{error:'Espera a que termine el análisis.'});
                const snapshot:Analysis=JSON.parse(await readFile(join(DATA,p.id,'result.json'),'utf8'));
                if(!snapshot.program||!/^listing-[a-f0-9-]{36}$/.test(snapshot.listingGeneration||''))return json(409,{error:'Regenera este proyecto para crear el modelo central.'});
                return json(200,JSON.parse(await readFile(join(DATA,p.id,snapshot.listingGeneration!,'program.json'),'utf8')));
            }

            if(req.method === 'GET' && action === 'decompile') {
                if(p.status !== 'ready' || (p.engine!=='internal'&&!p.persistent) || preparing.has(p.id)) return json(409,{error:'Espera a que termine el análisis.'});
                const snapshot:Analysis=JSON.parse(await readFile(join(DATA,p.id,'result.json'),'utf8'));
                const address=url.searchParams.get('address') || '';
                const directory=await readListingFunctions(join(DATA,p.id),snapshot.listingGeneration||'');
                if(!directory.some(f=>f.address===address)) return json(404,{error:'Función desconocida'});
                // Recheck after I/O: edits may have reserved this project meanwhile.
                if(p.status !== 'ready' || preparing.has(p.id)) return json(409,{error:'El análisis cambió. Recarga el proyecto.'});
                const cached=snapshot.functions.find(f=>f.address===address);
                if(p.engine==='internal'&&!cached)return json(404,{error:'Función interna no disponible'});
                return json(200,cached || await decompile(p.id,snapshot.listingGeneration!,address));
            }
            if(req.method === 'GET' && (action === 'listing' || action === 'listing-functions')) {
                if(p.status !== 'ready') return json(409,{error:'Espera a que termine el análisis.'});
                const snapshot:Analysis=JSON.parse(await readFile(join(DATA,p.id,'result.json'),'utf8'));
                if(action === 'listing-functions') return json(200,await readListingFunctions(join(DATA,p.id),snapshot.listingGeneration||''));
                return json(200,await readListing(join(DATA,p.id),snapshot.listingGeneration||'',url.searchParams));
            }
            if(req.method==='GET'&&['native-search','native-function','native-indirect'].includes(action||'')){
                if(p.engine!=='internal')return json(422,{error:'Consulta exclusiva del motor Rust'});
                if(p.status!=='ready')return json(409,{error:'Espera al análisis'});
                const args=action==='native-search'?['search',join(DATA,p.id),(url.searchParams.get('q')||'').slice(0,500),url.searchParams.get('kind')||'',url.searchParams.get('offset')||'0']:action==='native-function'?['function',join(DATA,p.id),url.searchParams.get('address')||'']:['indirect',join(DATA,p.id)];
                return json(200,await nativeQuery(args));
            }
            if (req.method === 'POST' && (action === 'reanalyze' || action === 'edit')) {
                let edit: Record<string,unknown> | undefined;
                if(action === 'edit') {
                    if(capabilities.features.programEditing.status==='unsupported')return json(422,{error:capabilities.features.programEditing.detail});
                    if(!capabilities.actions.edit.enabled)return json(capabilities.runtimeAvailable?409:503,{error:capabilities.actions.edit.reason});
                    if(!p.persistent || p.status!=='ready') return json(409,{error:'Regenera el análisis para crear un proyecto Ghidra persistente antes de editar.'});
                    edit=JSON.parse((await body(req,16000)).toString());
                    if(!edit || !capabilities.editOperations.includes(String(edit.operation)))return json(400,{error:'Operación inválida'});
                    if(p.engine==='internal'){
                        if(!['undo','redo','define-type'].includes(String(edit.operation)) && (typeof edit.address!=='string'||!/^[a-fA-F0-9]{1,16}$/.test(edit.address)))return json(400,{error:'Dirección inválida'});
                        if(edit.value!==undefined&&(typeof edit.value!=='string'||edit.value.length>8000))return json(400,{error:'Valor inválido'});
                    }else if(typeof edit.address!=='string'||!/^[a-fA-F0-9]+$/.test(edit.address)||typeof edit.value!=='string'||edit.value.length>8000||(edit.operation==='variable'&&(typeof edit.variableId!=='string'||!/^\d+$/.test(edit.variableId))))return json(400,{error:'Edición inválida'});
                }
                if (p.engine!=='internal'&&!available) return json(503, {error: 'El motor Ghidra no está disponible.'});
                if (decompiling || active?.id === p.id || ['queued','analyzing'].includes(p.status)) return json(409, {error: 'Este proyecto ya se está analizando.'});
                if ([...projects.values()].filter(p => ['queued','analyzing'].includes(p.status)).length >= 3) return json(429, {error: 'La cola de análisis está llena.'});
                // Reserve synchronously, before disk I/O, to prevent duplicate requests.
                const oldStatus = p.status;
                p.status = 'queued';
                preparing.add(p.id);
                try {
                    if(!edit) edits.delete(p.id);
                    if(p.engine==='internal')await rm(join(DATA,p.id,'native.cancel'),{force:true});
                    if(p.engine!=='internal')await rename(join(DATA,p.id,'result.json'), join(DATA,p.id,'previous-result.json')).catch(e => {if(e.code !== 'ENOENT') throw e;});
                    if(edit) {
                        await writeFile(join(DATA,p.id,'edit.json'),JSON.stringify(edit));
                        await writeFile(join(DATA,p.id,'edit-receipt.json'),JSON.stringify({ok:false,error:'El script no terminó'}));
                        edits.add(p.id);
                    }
                    delete p.error;
                    p.log = '';
                    await save(p);
                } catch(e) {edits.delete(p.id); p.status = oldStatus; throw e;} finally {preparing.delete(p.id);}
                runNext();
                return json(202,p);
            }
            if (req.method === 'GET' && !action)
                return json(200, p);
            if (req.method === 'GET' && action === 'result') {
                if (p.status !== 'ready')
                    return json(409, { error: 'El análisis aún no está disponible' });
                return json(200, JSON.parse(await readFile(join(DATA, p.id, 'result.json'), 'utf8')));
            }
            if (req.method === 'GET' && action === 'byte-search') {
                const pattern=(url.searchParams.get('pattern')||'').trim().split(/\s+/);
                if(pattern.length>64 || !pattern.every(v=>/^(?:[a-fA-F0-9]{2}|\?\?)$/.test(v)) || pattern.every(v=>v==='??')) return json(400,{error:'Usa bytes hexadecimales separados por espacios (máximo 64), con ?? como comodín.'});
                const bytes=await readFile(join(DATA,p.id,'input.bin'));
                const needle=pattern.map(v=>v==='??'?null:parseInt(v,16)); const offsets:number[]=[];
                for(let i=0;i<=bytes.length-needle.length && offsets.length<201;i++) if(needle.every((v,j)=>v===null || bytes[i+j]===v)) offsets.push(i);
                return json(200,{offsets:offsets.slice(0,200),truncated:offsets.length>200});
            }
            if (req.method === 'GET' && action === 'bytes') {
                const offset = Number(url.searchParams.get('offset') || 0);
                if (!Number.isSafeInteger(offset) || offset < 0 || offset > p.size)
                    return json(400, { error: 'Offset inválido' });
                const b = await readFile(join(DATA, p.id, 'input.bin'));
                return json(200, { offset, total: p.size, bytes: [...b.subarray(offset, offset + 256)] });
            }
            if (req.method === 'POST' && action === 'cancel') {
                if (p.status === 'queued' || p.status === 'analyzing') {
                    p.status = 'cancelled';
                    edits.delete(p.id);
                    if (active?.id === p.id)
                        kill(active.child);
                    if(internalJob?.id===p.id){await writeFile(join(DATA,p.id,'native.cancel'),'cancel');internalJob.child.kill('SIGKILL');}
                    await save(p);
                }
                return json(200, p);
            }
            if (req.method === 'PUT' && action === 'annotations') {
                const v = JSON.parse((await body(req, 16000)).toString());
                if (typeof v.address !== 'string' || !/^\w+:?[a-fA-F0-9]+$/.test(v.address) || typeof v.label !== 'string' || typeof v.comment !== 'string' || v.label.length > 200 || v.comment.length > 8000)
                    return json(400, { error: 'Anotación inválida' });
                const result: Analysis = JSON.parse(await readFile(join(DATA, p.id, 'result.json'), 'utf8'));
                if (!(await readListingFunctions(join(DATA,p.id),result.listingGeneration||'')).some(f => f.address === v.address))
                    return json(400, { error: 'Función desconocida' });
                p.annotations[v.address] = { label: v.label, comment: v.comment };
                await save(p);
                return json(200, p);
            }
        }
        const files: Record<string, [
            string,
            string
        ]> = { '/': ['frontend/index.html', 'text/html'], '/style.css': ['frontend/style.css', 'text/css'], '/app.js': ['dist/frontend/app.js', 'text/javascript'], '/code-view.js': ['dist/frontend/code-view.js', 'text/javascript'], '/explorer.js': ['dist/frontend/explorer.js', 'text/javascript'], '/listing-view.js': ['dist/frontend/listing-view.js', 'text/javascript'], '/capabilities-view.js': ['dist/frontend/capabilities-view.js','text/javascript'], '/cfg-graph.js': ['dist/frontend/cfg-graph.js','text/javascript'], '/cfg-layout.js': ['dist/frontend/cfg-layout.js','text/javascript'], '/vendor/three.module.js': ['node_modules/three/build/three.module.js','text/javascript'], '/vendor/three.core.js': ['node_modules/three/build/three.core.js','text/javascript'] };
        if (req.method === 'GET' && files[path]) {
            const [file, type] = files[path];
            res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store' });
            return res.end(await readFile(join(ROOT, file)));
        }
        json(404, { error: 'No encontrado' });
    }
    catch (e) {
        json((e as {
            status?: number;
        }).status || 500, { error: e instanceof Error ? e.message : String(e) });
    }
});
server.listen(port, '127.0.0.1', () => console.log(`Ghidra Web: http://${host} — motor seleccionado: ${settings.engine}; Ghidra ${available ? 'disponible' : 'no configurado'}`));
process.on('SIGINT', () => { if (active)
    kill(active.child); if(internalJob)internalJob.child.kill('SIGKILL'); server.close(); });
