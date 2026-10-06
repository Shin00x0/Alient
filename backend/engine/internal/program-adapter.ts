import {createHash} from 'node:crypto';
import {Program,address,range} from '../core/program/program.ts';
import type {EntityInput,ProgramSnapshot} from '../core/program/types.ts';
import type {Analysis,ListingInstruction} from '../../types.ts';
import type {Image} from './loader.ts';

/** Loader -> central program. File bytes remain in input.bin, never duplicated in the snapshot. */
export function createImageProgram(bytes:Buffer,image:Image):Program {
    const program=new Program({source:{sha256:createHash('sha256').update(bytes).digest('hex'),size:bytes.length},format:image.format,architecture:image.architecture});
    const entities:EntityInput[]=[{kind:'space',name:'ram',bits:64,endianness:'little'}];
    for(const region of image.regions){if(!region.size)continue;entities.push({kind:'memory',name:region.name,range:range(address('ram',region.address),region.size),permissions:region.permissions,backing:{fileOffset:region.offset,fileSize:region.fileSize,tail:'zero'},provenance:{origin:'loader',confidence:'confirmed'}});}
    program.reconcile(entities,'Importar espacios y memoria del binario');
    return program;
}

/** Keep analysis heuristics explicit; no inferred body becomes a confirmed function. */
export function recordAnalysis(program:Program,analysis:Analysis,rows:ListingInstruction[],previous?:ProgramSnapshot):Program {
    program.transaction('Registrar instrucciones, funciones y datos del análisis ARM64',tx=>{
        for(const row of rows)tx.put({kind:'instruction',address:address(row.space,row.address),size:row.bytes.split(' ').length,bytes:row.bytes.replaceAll(' ',''),text:row.text,decodeStatus:row.text.startsWith('.inst')?'unknown':'decoded',provenance:{origin:'analysis',confidence:row.text.startsWith('.inst')?'unknown':'inferred'}});
        for(const f of analysis.functions)tx.put({kind:'function',entry:address('ram',f.address),name:f.name,body:[range(address('ram',f.address),BigInt('0x'+f.end!)-BigInt('0x'+f.address)+1n)],provenance:{origin:'analysis',confidence:'inferred'}});
        for(const s of analysis.strings)tx.put({kind:'data',range:range(address('ram',s.address),BigInt('0x'+s.end!)-BigInt('0x'+s.address)+1n),dataType:'ascii-z',value:s.value,provenance:{origin:'analysis',confidence:'inferred'}});
    });
    let result=program;
    if(previous){result=Program.restore(previous);if(result.id!==program.id)throw Error('El modelo anterior pertenece a otro programa.');result.reconcile(program.snapshot().entities.map(({id,revision,...entity})=>entity as EntityInput),'Regenerar análisis ARM64');}
    analysis.program={id:result.id,revision:result.revision,schemaVersion:1};
    // Public DTOs carry semantic identity but remain presentation contracts, not the core model.
    const instructions=new Map(result.list('instruction').map(e=>[e.address.space+':'+e.address.offset,e]));
    for(const row of rows){const e=instructions.get(row.space+':'+BigInt('0x'+row.address).toString(16))!;row.id=e.id;row.revision=e.revision;}
    const functions=new Map(result.list('function').map(e=>[e.entry.offset,e]));
    for(const f of analysis.functions){const e=functions.get(BigInt('0x'+f.address).toString(16))!;f.id=e.id;f.revision=e.revision;}
    return result;
}
