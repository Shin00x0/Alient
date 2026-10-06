import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn,type ChildProcess} from 'node:child_process';
import {decodeArm64} from '../backend/engine/internal/arm64.ts';
import {analyzeInternal} from '../backend/engine/internal/index.ts';
import {loadImage} from '../backend/engine/internal/loader.ts';
import {markupText} from '../frontend/code-view.ts';
const wait=(ms:number)=>new Promise(r=>setTimeout(r,ms));
function elf(){
    const b=Buffer.alloc(0x114);b.set([127,69,76,70,2,1,1]);b.writeUInt16LE(2,16);b.writeUInt16LE(183,18);b.writeBigUInt64LE(0x400100n,24);b.writeBigUInt64LE(64n,32);b.writeUInt16LE(64,52);b.writeUInt16LE(56,54);b.writeUInt16LE(1,56);
    b.writeUInt32LE(1,64);b.writeUInt32LE(5,68);b.writeBigUInt64LE(0x100n,72);b.writeBigUInt64LE(0x400100n,80);b.writeBigUInt64LE(20n,96);b.writeBigUInt64LE(20n,104);
    [0xd28000e0,0x91000c00,0xb4000040,0xffffffff,0xd65f03c0].forEach((w,i)=>b.writeUInt32LE(w,0x100+i*4));return b;
}
test('internal ARM64 decoding preserves signed branches, 64-bit PC and unknown words',()=>{
    assert.equal(decodeArm64(0x17ffffff,0x1000000000000000n).target,0xffffffffffffffcn);
    assert.equal(decodeArm64(0x94000002,0x1000n).target,0x1008n);
    assert.equal(decodeArm64(0xd28000e0,0n).constant,7n);
    assert.match(decodeArm64(0x91000c00,0n).ir,/x0 \+ 3/);
    assert.equal(decodeArm64(0xd65f03c0,0n).flow,'return');
    assert.equal(decodeArm64(0xffffffff,0n).known,false);
    assert.equal(decodeArm64(0xd503201f,0n).text,'nop');
});
test('internal ELF loader checks bounds and produces explicitly partial IR',()=>{
    const bytes=elf(),{analysis,rows}=analyzeInternal(bytes,'minimal.elf');
    assert.equal(analysis.engine,'internal');assert.equal(rows.length,5);
    assert.equal(analysis.functions[0].decompileStatus,'partial');assert.match(analysis.functions[0].warning!,/1 instrucciones/);
    assert.ok(analysis.allReferences!.some(r=>r.to==='00400110'&&r.type==='CONDITIONAL_JUMP'));
    assert.equal(markupText(analysis.functions[0].codeLines!),analysis.functions[0].code);
    for(let n=0;n<64;n++)assert.throws(()=>loadImage(bytes.subarray(0,n)));
    const invalid=Buffer.from(bytes);invalid.writeBigUInt64LE(0xffffffffffffffffn,72);assert.throws(()=>loadImage(invalid),/rango/);
    const x86=Buffer.from(bytes);x86.writeUInt16LE(62,18);assert.throws(()=>loadImage(x86),/ARM64/);
    assert.throws(()=>loadImage(Buffer.from('MZunsupported')),/formato no soportado/);
});
test('internal Mach-O analysis extracts newline strings, xrefs and uncapped function listing',async()=>{
    const {analysis,rows}=analyzeInternal(await readFile('fixtures/sample-macho'),'sample');
    assert.equal(analysis.imageBase,'100000000');assert.equal(rows.length,31);assert.ok(rows.every(r=>!r.text.startsWith('.inst')));
    const string=analysis.strings.find(s=>s.value.includes('Ghidra Web static analysis fixture'));assert.ok(string);
    assert.ok(analysis.allReferences!.some(r=>r.to===string.address&&r.type==='DATA'));
    assert.ok(analysis.functions.some(f=>f.name==='_calculate_score'));
    const large=analyzeInternal(await readFile('fixtures/listing-large-macho'),'large');assert.equal(large.rows.length,1431);assert.ok(large.analysis.functions.length>200);
});
test('internal API operates with nonexistent Java/Ghidra and persists engine configuration', {timeout:30000},async()=>{
    const data=await mkdtemp(join(tmpdir(),'internal-engine-')),base='http://127.0.0.1:4312';let child:ChildProcess|undefined;
    async function start(){child=spawn(process.execPath,['--experimental-strip-types','backend/server.ts'],{env:{...process.env,PORT:'4312',DATA_DIR:data,GHIDRA_HOME:join(data,'no-ghidra'),JAVA_HOME:join(data,'no-java')},stdio:'pipe'});let log='';child.stderr!.on('data',b=>log+=b);for(let i=0;i<100;i++){try{if((await fetch(base+'/api/health')).ok)return;}catch{}if(child.exitCode!==null)throw Error(log);await wait(50);}throw Error('No inició el servidor: '+log);}
    async function stop(){if(child&&child.exitCode===null){const exited=new Promise<void>(resolve=>child!.once('exit',()=>resolve()));child.kill('SIGINT');await exited;}}
    async function ready(id:string){for(let i=0;i<100;i++){const p=await(await fetch(base+'/api/projects/'+id)).json();if(!['queued','analyzing'].includes(p.status)){assert.equal(p.status,'ready',p.error);return p;}await wait(50);}throw Error('Análisis no terminó');}
    try {
        await start();const health=await(await fetch(base+'/api/health')).json();assert.equal(health.ghidraAvailable,false);assert.equal(health.selectedEngine,'internal');assert.equal(health.engine,'ready');
        const engines=await(await fetch(base+'/api/engines')).json();assert.equal(engines.length,2);assert.equal(engines.find((c:{engine:string})=>c.engine==='ghidra').runtimeAvailable,false);
        assert.equal((await fetch(base+'/api/projects?engine=ghidra',{method:'POST',body:elf()})).status,503);
        assert.equal((await fetch(base+'/api/settings',{method:'PUT',body:JSON.stringify({engine:'invalid'})})).status,400);
        const upload=await fetch(base+'/api/projects?name=own.elf',{method:'POST',body:elf()});assert.equal(upload.status,202);const project=await upload.json();await ready(project.id);
        const caps=await(await fetch(base+'/api/projects/'+project.id+'/capabilities')).json();assert.equal(caps.engine,'internal');assert.equal(caps.features.types.status,'partial');assert.equal(caps.actions.edit.enabled,true);
        const result=await(await fetch(base+'/api/projects/'+project.id+'/result')).json();assert.equal(result.engine,'internal');
        const model=await(await fetch(base+'/api/projects/'+project.id+'/program')).json();assert.equal(model.id,result.program.id);assert.equal(model.revision,result.program.revision);assert.equal(model.schema_version,2);assert.equal(Object.keys(model.instructions).length,5);assert.equal(result.nativeEngine,'rust');
        const listing=await(await fetch(base+'/api/projects/'+project.id+'/listing')).json();assert.equal(listing.rows.length,5);
        const decompile=await fetch(base+'/api/projects/'+project.id+'/decompile?address=00400100');assert.equal(decompile.status,200);assert.equal((await decompile.json()).decompileStatus,'partial');
        assert.equal((await fetch(base+'/api/projects/'+project.id+'/edit',{method:'POST',body:'{}'})).status,400);
        assert.equal((await fetch(base+'/api/projects/'+project.id+'/annotations',{method:'PUT',body:JSON.stringify({address:'00400100',label:'entrada',comment:'nota'})})).status,200);
        assert.equal((await fetch(base+'/api/projects/'+project.id+'/reanalyze',{method:'POST'})).status,202);await ready(project.id);
        const revised=await(await fetch(base+'/api/projects/'+project.id+'/result')).json();assert.notEqual(result.listingGeneration,revised.listingGeneration);assert.deepEqual(revised.program,result.program);assert.deepEqual(await(await fetch(base+'/api/projects/'+project.id+'/program')).json(),model);
        assert.equal((await fetch(base+'/api/settings',{method:'PUT',body:JSON.stringify({engine:'ghidra'})})).status,200);
        await stop();await start();assert.equal((await(await fetch(base+'/api/settings')).json()).engine,'ghidra');
        const persisted=await(await fetch(base+'/api/projects/'+project.id)).json();assert.equal(persisted.engine,'internal');assert.deepEqual(await(await fetch(base+'/api/projects/'+project.id+'/program')).json(),model);assert.equal((await(await fetch(base+'/api/projects/'+project.id+'/capabilities')).json()).engine,'internal');assert.equal(persisted.annotations['00400100'].label,'entrada');
        assert.equal((await fetch(base+'/api/projects/'+project.id+'/reanalyze',{method:'POST'})).status,202);await ready(project.id);
        async function edit(command:unknown){assert.equal((await fetch(base+'/api/projects/'+project.id+'/edit',{method:'POST',body:JSON.stringify(command)})).status,202);return ready(project.id);}
        await edit({operation:'rename',address:'00400100',value:'native_entry'});
        let changed=await(await fetch(base+'/api/projects/'+project.id+'/result')).json();assert.equal(changed.functions[0].name,'native_entry');
        const search=await(await fetch(base+'/api/projects/'+project.id+'/native-search?q=native_entry')).json();assert.ok(search.total>0);
        const fn=await(await fetch(base+'/api/projects/'+project.id+'/native-function?address=00400100')).json();assert.ok(fn.dataflow);assert.equal(fn.name,'native_entry');
        await stop();await start();await edit({operation:'undo'});
        changed=await(await fetch(base+'/api/projects/'+project.id+'/result')).json();assert.equal(changed.functions[0].name,result.functions[0].name);
        await edit({operation:'redo'});changed=await(await fetch(base+'/api/projects/'+project.id+'/result')).json();assert.equal(changed.functions[0].name,'native_entry');
        const rejected=await edit({operation:'rename',address:'00400100',value:'invalid name'});assert.ok(rejected.error);
        assert.equal((await(await fetch(base+'/api/projects/'+project.id+'/result')).json()).listingGeneration,changed.listingGeneration);
    } finally {await stop();await rm(data,{recursive:true,force:true});}
});
