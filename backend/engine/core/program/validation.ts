import {address,range,offset,end,compare,contains} from './address.ts';
import type {Entity,EntityInput,Address,AddressRange,MemoryInput,ProgramDescriptor} from './types.ts';

export function checkDescriptor(d:ProgramDescriptor){
    if(!d||!d.source||!/^[a-f0-9]{64}$/.test(d.source.sha256)||!Number.isSafeInteger(d.source.size)||d.source.size<0||typeof d.format!=='string'||!d.format||typeof d.architecture!=='string'||!d.architecture)throw Error('Descriptor de programa inválido.');
}
function text(value:unknown){if(typeof value!=='string')throw Error('Texto de entidad inválido.');}
function canonicalAddress(a:Address){if(!a||JSON.stringify(address(a.space,a.offset))!==JSON.stringify({space:a.space,offset:a.offset}))throw Error('Dirección no canónica.');}
function canonicalRange(r:AddressRange){if(!r)throw Error('Rango ausente.');canonicalAddress(r.start);if(range(r.start,r.size).size!==r.size)throw Error('Tamaño no canónico.');}
export function checkInput(e:EntityInput){
    if(!e||!['space','memory','instruction','function','data'].includes(e.kind))throw Error('Tipo de entidad desconocido.');
    if(e.kind==='space'){
        address(e.name,0n);if(!Number.isInteger(e.bits)||e.bits<1||e.bits>64||!['little','big'].includes(e.endianness))throw Error('Espacio de direcciones inválido.');return;
    }
    if(!e.provenance||!['loader','analysis','user'].includes(e.provenance.origin)||!['confirmed','inferred','unknown'].includes(e.provenance.confidence))throw Error('Procedencia inválida.');
    if(e.kind==='memory'){
        text(e.name);canonicalRange(e.range);
        if(!/^[r-][w-][x-]$/.test(e.permissions)||!e.backing||!Number.isSafeInteger(e.backing.fileOffset)||e.backing.fileOffset<0||!Number.isSafeInteger(e.backing.fileSize)||e.backing.fileSize<0||BigInt(e.backing.fileSize)>BigInt(e.range.size)||!['zero','unknown'].includes(e.backing.tail))throw Error('Mapeo de memoria inválido.');
    } else if(e.kind==='instruction'){
        canonicalAddress(e.address);text(e.text);if(!Number.isSafeInteger(e.size)||e.size<1||e.size>256||typeof e.bytes!=='string'||!/^(?:[0-9a-f]{2})+$/.test(e.bytes)||e.bytes.length!==e.size*2||!['decoded','unknown'].includes(e.decodeStatus))throw Error('Instrucción inválida.');range(e.address,e.size);
    } else if(e.kind==='function'){
        canonicalAddress(e.entry);text(e.name);if(!e.name||!Array.isArray(e.body)||!e.body.length)throw Error('Cuerpo de función vacío.');e.body.forEach(canonicalRange);
        if(e.body.some(r=>r.start.space!==e.entry.space)||!e.body.some(r=>contains(r,e.entry)))throw Error('La entrada no pertenece al cuerpo de la función.');
        noOverlap(e.body);
    } else {canonicalRange(e.range);text(e.dataType);if(!e.dataType)throw Error('Tipo de dato vacío.');if(e.value!==undefined)text(e.value);}
}
export function noOverlap(ranges:AddressRange[]){
    const sorted=[...ranges].sort((a,b)=>compare(a.start,b.start));
    for(let i=1;i<sorted.length;i++)if(sorted[i-1].start.space===sorted[i].start.space&&end(sorted[i-1])>offset(sorted[i].start))throw Error('Rangos superpuestos en el mismo espacio.');
}
export function memoryIndex(entities:Iterable<Entity>):Map<string,Entity<MemoryInput>[]> {
    const result=new Map<string,Entity<MemoryInput>[]>();
    for(const e of entities)if(e.kind==='memory'){const list=result.get(e.range.start.space)||[];list.push(e);result.set(e.range.start.space,list);}
    for(const list of result.values())list.sort((a,b)=>compare(a.range.start,b.range.start));
    return result;
}
export function memoryAt(index:Map<string,Entity<MemoryInput>[]>,a:Address):Entity<MemoryInput>|undefined {
    const list=index.get(a.space)||[];let low=0,high=list.length;
    while(low<high){const mid=(low+high)>>>1;if(offset(list[mid].range.start)<=offset(a))low=mid+1;else high=mid;}
    const found=list[low-1];return found&&contains(found.range,a)?found:undefined;
}
export function checkEntities(entities:Map<string,Entity>,descriptor:ProgramDescriptor){
    const spaces=new Map([...entities.values()].filter(e=>e.kind==='space').map(e=>[e.name,e]));
    const index=memoryIndex(entities.values()),units:AddressRange[]=[];
    function checkRange(r:AddressRange){const space=spaces.get(r.start.space);if(!space)throw Error('Espacio de direcciones inexistente.');if(end(r)>1n<<BigInt(space.bits))throw Error('Rango fuera del espacio de direcciones.');}
    function mapped(r:AddressRange){
        checkRange(r);let cursor=offset(r.start);
        while(cursor<end(r)){const m=memoryAt(index,address(r.start.space,cursor));if(!m)throw Error('Entidad en memoria no mapeada.');cursor=end(m.range);}
    }
    for(const list of index.values())noOverlap(list.map(m=>m.range));
    for(const e of entities.values()){
        checkInput(e);
        if(e.kind==='memory'){checkRange(e.range);if(e.backing.fileSize&&e.backing.fileOffset+e.backing.fileSize>descriptor.source.size)throw Error('Mapeo fuera del archivo original.');}
        if(e.kind==='instruction'){const r=range(e.address,e.size);mapped(r);units.push(r);}
        if(e.kind==='data'){mapped(e.range);units.push(e.range);}
        if(e.kind==='function')e.body.forEach(mapped);
    }
    noOverlap(units);
}
