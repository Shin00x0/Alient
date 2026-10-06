import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import {Program,address,range,entityId,type EntityInput,type ProgramTransaction} from '../backend/engine/core/program/program.ts';
import {analyzeInternal} from '../backend/engine/internal/index.ts';
const source=Buffer.from([1,2,3,4,5,6,7,8]);
const descriptor={source:{sha256:createHash('sha256').update(source).digest('hex'),size:source.length},format:'fixture',architecture:'test:64'};
const provenance={origin:'analysis',confidence:'inferred'} as const;
const at=(value:bigint|string)=>address('ram',value);
function seeded(){
    const p=new Program(descriptor);
    p.transaction('initial',tx=>{
        tx.put({kind:'space',name:'ram',bits:64,endianness:'little'});
        tx.put({kind:'space',name:'overlay',bits:64,endianness:'little'});
        tx.put({kind:'memory',name:'text',range:range(at('fffffffffffffff0'),8),permissions:'r-x',backing:{fileOffset:0,fileSize:8,tail:'zero'},provenance});
        tx.put({kind:'memory',name:'bss',range:range(at('fffffffffffffff8'),8),permissions:'rw-',backing:{fileOffset:0,fileSize:0,tail:'zero'},provenance});
        tx.put({kind:'memory',name:'overlay',range:range(address('overlay','fffffffffffffff0'),8),permissions:'r--',backing:{fileOffset:0,fileSize:8,tail:'unknown'},provenance});
        tx.put({kind:'instruction',address:at('fffffffffffffff0'),size:4,bytes:'01020304',text:'example',decodeStatus:'decoded',provenance});
        tx.put({kind:'data',range:range(at('fffffffffffffff4'),4),dataType:'bytes',provenance});
        tx.put({kind:'function',entry:at('fffffffffffffff0'),name:'entry',body:[range(at('fffffffffffffff0'),4)],provenance});
    });return p;
}
test('program preserves 64-bit boundaries, separate spaces, file mappings and zero tails',()=>{
    const p=seeded();
    assert.deepEqual([...p.readMemory(source,at('fffffffffffffff6'),10)],[7,8,0,0,0,0,0,0,0,0]);
    assert.equal(p.fileOffset(at('fffffffffffffff7')),7);assert.equal(p.fileOffset(at('fffffffffffffff8')),undefined);
    assert.equal(p.addressesForFileOffset(0).length,2);
    assert.ok(p.instructionAt(at('fffffffffffffff3')));assert.equal(p.instructionAt(at('fffffffffffffff4')),undefined);
    assert.ok(p.dataAt(at('fffffffffffffff4')));assert.equal(p.functionsAt(at('fffffffffffffff1')).length,1);
    assert.equal(p.instructionAt(address('overlay','fffffffffffffff0')),undefined);
    assert.throws(()=>p.readMemory(source,at('ffffffffffffffff'),2),/desborda/);
    assert.throws(()=>p.readMemory(Buffer.alloc(8),at('fffffffffffffff0'),1),/no corresponde/);
    assert.throws(()=>range(at('0'),Number.MAX_SAFE_INTEGER+1),/impreciso/);
    assert.throws(()=>p.readMemory(source,at('10'),1),/no mapeada/);
    const bss=p.list('memory').find(m=>m.name==='bss')!;
    p.transaction('mark unknown',tx=>tx.put({...bss,backing:{...bss.backing,tail:'unknown'}}));
    assert.throws(()=>p.readMemory(source,at('fffffffffffffff8'),1),/sin contenido/);
});
test('transactions preserve IDs, isolate callers, reject stale revisions and retain deletion/recreation history',()=>{
    const p=seeded(),fn=p.list('function')[0],first=p.revision;
    assert.throws(()=>Object.assign(p,{id:'changed'}),TypeError);
    assert.throws(()=>p.transaction('async',async tx=>{await Promise.resolve();tx.remove(fn.id);}),/síncronas/);
    const c=p.transaction('rename',tx=>tx.put({...fn,name:'renamed'}))!;
    assert.deepEqual(c.updated,[fn.id]);assert.equal(p.get(fn.id)!.revision,first+1);
    const snapshot=p.snapshot();snapshot.entities.length=0;assert.ok(p.list('function').length);
    const same=p.transaction('unchanged',tx=>tx.put(p.get(fn.id)!));assert.equal(same,undefined);assert.equal(p.revision,first+1);
    assert.throws(()=>p.transaction('stale',()=>{},first),/Conflicto/);
    let escaped:ProgramTransaction|undefined;p.transaction('empty',tx=>{escaped=tx;});assert.throws(()=>escaped!.remove(fn.id),/terminó/);
    const before=p.snapshot();assert.throws(()=>p.transaction('rollback',tx=>{tx.remove(fn.id);throw Error('stop');}),/stop/);assert.deepEqual(p.snapshot(),before);
    assert.throws(()=>p.transaction('nested',()=>{p.transaction('inner',()=>{});}),/anidadas/);
    p.transaction('delete',tx=>tx.remove(fn.id));p.transaction('restore function',tx=>tx.put({...fn,name:'reborn'}));
    assert.ok(p.get(fn.id)!.revision>fn.revision);assert.equal(p.changesSince(first).length,3);
    assert.deepEqual(Program.restore(JSON.parse(JSON.stringify(p.snapshot()))).snapshot(),p.snapshot());
});
test('invalid graph updates roll back atomically, including mappings, overlaps and function bodies',()=>{
    const p=seeded(),before=p.snapshot(),space=p.list('space').find(s=>s.name==='ram')!;
    assert.throws(()=>p.transaction('delete space',tx=>tx.remove(space.id)),/inexistente/);
    assert.throws(()=>p.transaction('overlap',tx=>tx.put({kind:'data',range:range(at('fffffffffffffff2'),2),dataType:'u16',provenance})),/superpuestos/);
    assert.throws(()=>p.transaction('bad function',tx=>tx.put({kind:'function',entry:at('1'),name:'bad',body:[range(at('2'),2)],provenance})),/entrada/);
    assert.throws(()=>p.transaction('bad instruction',tx=>tx.put({kind:'instruction',address:at('fffffffffffffff0'),size:4,bytes:'00',text:'bad',decodeStatus:'decoded',provenance})),/Instrucción/);
    const m=p.list('memory')[0];assert.throws(()=>p.transaction('bad backing',tx=>tx.put({...m,backing:{fileOffset:100,fileSize:8,tail:'zero'}})),/archivo/);
    assert.deepEqual(p.snapshot(),before);
    const narrow=new Program(descriptor);assert.throws(()=>narrow.transaction('overflow',tx=>{tx.put({kind:'space',name:'ram',bits:16,endianness:'little'});tx.put({kind:'memory',name:'bad',range:range(at('ffff'),2),permissions:'r--',backing:{fileOffset:0,fileSize:0,tail:'zero'},provenance});}),/fuera del espacio/);
});
test('snapshot validation rejects unknown schemas, broken IDs, revisions and incomplete journals',()=>{
    const snapshot=seeded().snapshot();
    assert.throws(()=>Program.restore({...snapshot,schemaVersion:2}),/Versión/);
    const badId=structuredClone(snapshot);badId.entities[0].id='forged';assert.throws(()=>Program.restore(badId),/Identidad/);
    const badRevision=structuredClone(snapshot);badRevision.entities[0].revision=900;assert.throws(()=>Program.restore(badRevision),/revisión/);
    assert.throws(()=>Program.restore({...snapshot,changes:[]}),/inválido/);
    const badJournal=structuredClone(snapshot);badJournal.changes[0].created=[];assert.throws(()=>Program.restore(badJournal),/historial/);
});
test('internal analysis consumes the program model and retains entity identities on regeneration',async()=>{
    const bytes=await readFile('fixtures/sample-macho');
    const first=analyzeInternal(bytes,'first'),snapshot=first.program.snapshot();
    assert.equal(first.program.list('instruction').length,31);assert.ok(first.program.list('data').length);
    assert.equal(first.rows[0].id,first.program.instructionAt(at(first.rows[0].address))!.id);
    assert.equal(first.analysis.functions[0].id,first.program.functionsAt(at(first.analysis.functions[0].address))[0].id);
    const next=analyzeInternal(bytes,'different file label',JSON.parse(JSON.stringify(snapshot)));
    assert.deepEqual(next.program.snapshot(),snapshot);assert.equal(next.analysis.program!.revision,snapshot.revision);
    const fn=next.program.list('function')[0];const id=entityId(next.program.id,fn);
    next.program.transaction('rename only',tx=>tx.put({...fn,name:'new_name'}));assert.equal(next.program.get(id)!.revision,snapshot.revision+1);
    assert.equal(next.program.list('instruction')[0].revision,first.program.list('instruction')[0].revision);
    const entities=next.program.snapshot().entities.map(({id,revision,...e})=>e as EntityInput);
    assert.throws(()=>next.program.reconcile([...entities,entities[0]],'duplicate'),/duplicada/);
    assert.equal(next.program.get(id)!.revision,snapshot.revision+1);
});
