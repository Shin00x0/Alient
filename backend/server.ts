import { createServer } from 'node:http';
import { readFile, writeFile, mkdir, readdir, rename, access } from 'node:fs/promises';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID, createHash } from 'node:crypto';
import { spawn, type ChildProcess } from 'node:child_process';
import { constants, existsSync } from 'node:fs';
import type { Project, Analysis } from './types.ts';
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DATA = process.env.DATA_DIR || join(ROOT, 'data');
await mkdir(DATA, { recursive: true });
const port = Number(process.env.PORT || 4310), host = `127.0.0.1:${port}`;
const projects = new Map<string, Project>();
const preparing = new Set<string>();
const edits = new Set<string>();
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
    if (active || !available)
        return;
    const p = [...projects.values()].find(p => p.status === 'queued' && !preparing.has(p.id));
    if (!p)
        return;
    p.status = 'analyzing';
    p.log = 'Iniciando análisis estático de Ghidra…\n';
    void save(p);
    const dir = join(DATA, p.id);
    const editing = edits.has(p.id);
    const reuse = p.persistent && existsSync(join(dir,'analysis.gpr'));
    const args = [dir, 'analysis', ...(reuse ? ['-process','input.bin'] : ['-overwrite','-import',join(dir,'input.bin')]), '-scriptPath',join(ROOT,'scripts')];
    if(editing) args.push('-noanalysis','-preScript','MutateWeb.java',join(dir,'edit.json'),join(dir,'edit-receipt.json'));
    args.push('-postScript','ExportWeb.java',join(dir,'result.json'),'-analysisTimeoutPerFile','300','-max-cpu','2');
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
            JSON.parse(await readFile(join(dir, 'result.json'), 'utf8'));
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
            return json(200, { engine: available ? 'ready' : 'missing', message: available ? 'Ghidra disponible' : 'Revisa GHIDRA_HOME, JAVA_HOME y el decompilador nativo; consulta README.md.', busy: !!active });
        if (path === '/api/projects' && req.method === 'GET')
            return json(200, [...projects.values()].map(({ log, ...p }) => p).reverse());
        if (path === '/api/projects' && req.method === 'POST') {
            if (!available)
                return json(503, { error: 'El motor Ghidra no está disponible. Consulta README.md.' });
            if ([...projects.values()].filter(p => ['queued', 'analyzing'].includes(p.status)).length >= 3)
                return json(429, { error: 'Hay tres análisis pendientes. Espera a que terminen.' });
            const buffer = await body(req, 32 * 1024 * 1024);
            if (!buffer.length)
                return json(400, { error: 'Archivo vacío' });
            const id = randomUUID();
            const p: Project = { id, name: (url.searchParams.get('name') || 'binary').slice(0, 200), created: new Date().toISOString(), status: 'queued', log: '', size: buffer.length, sha256: createHash('sha256').update(buffer).digest('hex'), annotations: {} };
            await mkdir(join(DATA, id));
            await writeFile(join(DATA, id, 'input.bin'), buffer);
            await save(p);
            projects.set(id, p);
            runNext();
            return json(202, p);
        }
        const match = path.match(/^\/api\/projects\/([a-f0-9-]{36})(?:\/(result|annotations|cancel|bytes|reanalyze|edit|byte-search))?$/);
        if (match) {
            const p = projects.get(match[1]);
            if (!p)
                return json(404, { error: 'Proyecto no encontrado' });
            const action = match[2];
            if (req.method === 'POST' && (action === 'reanalyze' || action === 'edit')) {
                let edit: Record<string,unknown> | undefined;
                if(action === 'edit') {
                    if(!p.persistent || p.status!=='ready') return json(409,{error:'Regenera el análisis para crear un proyecto Ghidra persistente antes de editar.'});
                    edit=JSON.parse((await body(req,16000)).toString());
                    if(!edit || !['rename','comment','function-comment','signature','bookmark','variable'].includes(String(edit.operation)) || typeof edit.address!=='string' || !/^[a-fA-F0-9]+$/.test(edit.address) || typeof edit.value!=='string' || edit.value.length>8000 || (edit.operation==='variable' && (typeof edit.variableId!=='string' || !/^\d+$/.test(edit.variableId))) || (edit.dataType!==undefined && typeof edit.dataType!=='string')) return json(400,{error:'Edición inválida'});
                }
                if (!available) return json(503, {error: 'El motor Ghidra no está disponible.'});
                if (active?.id === p.id || ['queued','analyzing'].includes(p.status)) return json(409, {error: 'Este proyecto ya se está analizando.'});
                if ([...projects.values()].filter(p => ['queued','analyzing'].includes(p.status)).length >= 3) return json(429, {error: 'La cola de análisis está llena.'});
                // Reserve synchronously, before disk I/O, to prevent duplicate requests.
                const oldStatus = p.status;
                p.status = 'queued';
                preparing.add(p.id);
                try {
                    await rename(join(DATA,p.id,'result.json'), join(DATA,p.id,'previous-result.json')).catch(e => {if(e.code !== 'ENOENT') throw e;});
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
                    if (active?.id === p.id)
                        kill(active.child);
                    await save(p);
                }
                return json(200, p);
            }
            if (req.method === 'PUT' && action === 'annotations') {
                const v = JSON.parse((await body(req, 16000)).toString());
                if (typeof v.address !== 'string' || !/^\w+:?[a-fA-F0-9]+$/.test(v.address) || typeof v.label !== 'string' || typeof v.comment !== 'string' || v.label.length > 200 || v.comment.length > 8000)
                    return json(400, { error: 'Anotación inválida' });
                const result: Analysis = JSON.parse(await readFile(join(DATA, p.id, 'result.json'), 'utf8'));
                if (!result.functions.some(f => f.address === v.address))
                    return json(400, { error: 'Función desconocida' });
                p.annotations[v.address] = { label: v.label, comment: v.comment };
                await save(p);
                return json(200, p);
            }
        }
        const files: Record<string, [
            string,
            string
        ]> = { '/': ['frontend/index.html', 'text/html'], '/style.css': ['frontend/style.css', 'text/css'], '/app.js': ['dist/frontend/app.js', 'text/javascript'], '/code-view.js': ['dist/frontend/code-view.js', 'text/javascript'] };
        if (req.method === 'GET' && files[path]) {
            const [file, type] = files[path];
            res.writeHead(200, { 'Content-Type': type });
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
server.listen(port, '127.0.0.1', () => console.log(`Ghidra Web: http://${host} — motor ${available ? 'disponible' : 'no configurado'}`));
process.on('SIGINT', () => { if (active)
    kill(active.child); server.close(); });
