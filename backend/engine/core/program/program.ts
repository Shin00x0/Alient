import {createHash} from 'node:crypto';
import {address,range,offset,end,contains} from './address.ts';
import {checkDescriptor,checkInput,checkEntities,memoryIndex,memoryAt} from './validation.ts';
import type {Address,AddressRange,ChangeSet,DataInput,Entity,EntityInput,EntityKind,FunctionInput,InstructionInput,MemoryInput,ProgramDescriptor,ProgramSnapshot} from './types.ts';
export * from './types.ts';
export {address,range,contains} from './address.ts';

/** Property order never changes entity identity or creates a spurious revision. */
function stable(value:unknown):string {
    if(Array.isArray(value))return '['+value.map(stable).join(',')+']';
    if(value!==null&&typeof value==='object')return '{'+Object.entries(value).filter(([,v])=>v!==undefined).sort(([a],[b])=>a<b?-1:a>b?1:0).map(([k,v])=>JSON.stringify(k)+':'+stable(v)).join(',')+'}';
    return JSON.stringify(value);
}
const hash=(s:string)=>createHash('sha256').update(s).digest('hex');
const input=(entity:Entity):EntityInput=>{const {id,revision,...rest}=entity;return rest;};
const copy=<T>(value:T):T=>structuredClone(value);
export function programId(descriptor:ProgramDescriptor):string {checkDescriptor(descriptor);return 'program-'+hash(stable(descriptor));}
export function entityId(program:string,value:EntityInput):string {
    checkInput(value);
    const key=value.kind==='space'?value.name:value.kind==='function'?value.entry:value.kind==='instruction'?value.address:value.range.start;
    return program+':'+value.kind+':'+hash(stable(key));
}
export interface ProgramTransaction {put(entity:EntityInput):string;remove(id:string):void;get(id:string):EntityInput|undefined}

/** Owns semantic identities and atomic revisions; contains no rendering or Ghidra dependencies. */
export class Program {
    #id:string;
    #descriptor:ProgramDescriptor;
    #revision=0;
    #entities=new Map<string,Entity>();
    #changes:ChangeSet[]=[];
    #editing=false;
    #memory?:Map<string,Entity<MemoryInput>[]>;
    #units?:Map<string,{range:AddressRange;entity:Entity<InstructionInput|DataInput>}[]>;
    constructor(descriptor:ProgramDescriptor){checkDescriptor(descriptor);this.#descriptor=copy(descriptor);this.#id=programId(descriptor);}
    get id():string{return this.#id;}
    get descriptor():ProgramDescriptor{return copy(this.#descriptor);}
    get revision():number{return this.#revision;}
    get(id:string):Entity|undefined {const e=this.#entities.get(id);return e?copy(e):undefined;}
    list<K extends EntityKind>(kind:K):Entity<Extract<EntityInput,{kind:K}>>[] {
        return [...this.#entities.values()].filter(e=>e.kind===kind).map(copy) as Entity<Extract<EntityInput,{kind:K}>>[];
    }
    changesSince(revision:number):ChangeSet[]{if(!Number.isSafeInteger(revision)||revision<0||revision>this.#revision)throw Error('Revisión inválida.');return copy(this.#changes.filter(c=>c.revision>revision));}
    transaction(reason:string,edit:(tx:ProgramTransaction)=>void,expectedRevision=this.#revision):ChangeSet|undefined {
        if(this.#editing)throw Error('No se permiten transacciones anidadas.');
        if(expectedRevision!==this.#revision)throw Error('Conflicto de revisión: recarga el programa.');
        if(typeof reason!=='string'||!reason.trim())throw Error('La transacción necesita un motivo.');
        const next=new Map(this.#entities);let open=true;this.#editing=true;
        const active=()=>{if(!open)throw Error('La transacción ya terminó.');};
        const tx:ProgramTransaction={
            put:value=>{active();const item=copy(value),id=entityId(this.id,item);next.set(id,{...item,id,revision:0});return id;},
            remove:id=>{active();if(!next.delete(id))throw Error('Entidad inexistente.');},
            get:id=>{active();const item=next.get(id);return item?copy(input(item)):undefined;}
        };
        try {
            const returned=edit(tx) as unknown;
            if(returned&&typeof (returned as {then?:unknown}).then==='function'){void Promise.resolve(returned).catch(()=>{});throw Error('Las transacciones deben ser síncronas.');}
            open=false;
            checkEntities(next,this.#descriptor);
            const change:ChangeSet={revision:this.#revision+1,reason,created:[],updated:[],deleted:[]};
            for(const [id,item] of next){const old=this.#entities.get(id);if(!old)change.created.push(id);else if(stable(input(old))!==stable(input(item)))change.updated.push(id);else next.set(id,old);}
            for(const id of this.#entities.keys())if(!next.has(id))change.deleted.push(id);
            if(!change.created.length&&!change.updated.length&&!change.deleted.length)return undefined;
            if(!Number.isSafeInteger(change.revision))throw Error('Límite de revisiones alcanzado.');
            for(const id of [...change.created,...change.updated])next.set(id,{...next.get(id)!,revision:change.revision});
            change.created.sort();change.updated.sort();change.deleted.sort();
            this.#entities=next;this.#revision=change.revision;this.#changes.push(change);this.#memory=undefined;this.#units=undefined;
            return copy(change);
        } finally {open=false;this.#editing=false;}
    }
    /** Replace an analysis snapshot while retaining unchanged IDs and revisions. */
    reconcile(values:EntityInput[],reason:string):ChangeSet|undefined {
        const desired=new Set<string>();
        return this.transaction(reason,tx=>{
            for(const value of values){const id=entityId(this.id,value);if(desired.has(id))throw Error('Identidad de entidad duplicada.');desired.add(id);tx.put(value);}
            for(const id of this.#entities.keys())if(!desired.has(id))tx.remove(id);
        });
    }
    #index(){return this.#memory??=memoryIndex(this.#entities.values());}
    memoryAt(a:Address):Entity<MemoryInput>|undefined {const found=memoryAt(this.#index(),address(a.space,a.offset));return found?copy(found):undefined;}
    #unitAt(a:Address):Entity<InstructionInput|DataInput>|undefined {
        a=address(a.space,a.offset);
        if(!this.#units){this.#units=new Map();for(const entity of this.#entities.values())if(entity.kind==='instruction'||entity.kind==='data'){
            const r=entity.kind==='instruction'?range(entity.address,entity.size):entity.range,list=this.#units.get(r.start.space)||[];list.push({range:r,entity});this.#units.set(r.start.space,list);
        }for(const list of this.#units.values())list.sort((a,b)=>offset(a.range.start)<offset(b.range.start)?-1:1);}
        const list=this.#units.get(a.space)||[];let low=0,high=list.length;
        while(low<high){const mid=(low+high)>>>1;if(offset(list[mid].range.start)<=offset(a))low=mid+1;else high=mid;}
        const found=list[low-1];return found&&contains(found.range,a)?copy(found.entity):undefined;
    }
    instructionAt(a:Address):Entity<InstructionInput>|undefined {const e=this.#unitAt(a);return e?.kind==='instruction'?e:undefined;}
    dataAt(a:Address):Entity<DataInput>|undefined {const e=this.#unitAt(a);return e?.kind==='data'?e:undefined;}
    functionsAt(a:Address):Entity<FunctionInput>[] {return this.list('function').filter(e=>e.body.some(r=>contains(r,a)));}
    fileOffset(a:Address):number|undefined {
        const m=memoryAt(this.#index(),address(a.space,a.offset));if(!m)return undefined;
        const delta=offset(a)-offset(m.range.start);
        return delta<BigInt(m.backing.fileSize)?m.backing.fileOffset+Number(delta):undefined;
    }
    addressesForFileOffset(fileOffset:number):Address[] {
        if(!Number.isSafeInteger(fileOffset)||fileOffset<0||fileOffset>=this.#descriptor.source.size)throw Error('Offset de archivo inválido.');
        return this.list('memory').filter(m=>fileOffset>=m.backing.fileOffset&&fileOffset<m.backing.fileOffset+m.backing.fileSize).map(m=>address(m.range.start.space,offset(m.range.start)+BigInt(fileOffset-m.backing.fileOffset)));
    }
    readMemory(source:Uint8Array,start:Address,length:number):Uint8Array {
        if(!Number.isSafeInteger(length)||length<0||length>1024*1024)throw Error('Lectura de memoria inválida: máximo 1 MiB.');
        if(source.length!==this.#descriptor.source.size||createHash('sha256').update(source).digest('hex')!==this.#descriptor.source.sha256)throw Error('El archivo no corresponde al programa.');
        start=address(start.space,start.offset);if(length)range(start,length);
        const output=new Uint8Array(length);let done=0;
        while(done<length){const at=address(start.space,offset(start)+BigInt(done)),m=memoryAt(this.#index(),at);if(!m)throw Error('Memoria no mapeada.');
            const delta=offset(at)-offset(m.range.start),remaining=BigInt(length-done),chunk=Number(end(m.range)-offset(at)<remaining?end(m.range)-offset(at):remaining);
            const fileLeft=BigInt(m.backing.fileSize)-delta,fileCount=fileLeft<=0n?0:Number(fileLeft<BigInt(chunk)?fileLeft:BigInt(chunk));
            if(fileCount){const position=m.backing.fileOffset+Number(delta);output.set(source.subarray(position,position+fileCount),done);}
            if(fileCount<chunk&&m.backing.tail==='unknown')throw Error('Memoria sin contenido conocido.');
            done+=chunk;
        }
        return output;
    }
    snapshot():ProgramSnapshot {return copy({schemaVersion:1,id:this.id,descriptor:this.#descriptor,revision:this.#revision,entities:[...this.#entities.values()].sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0),changes:this.#changes});}
    static restore(value:unknown):Program {
        if(!value||typeof value!=='object'||(value as {schemaVersion?:number}).schemaVersion!==1)throw Error('Versión de modelo de programa no soportada.');
        const s=value as ProgramSnapshot,p=new Program(s.descriptor);
        if(s.id!==p.id||!Number.isSafeInteger(s.revision)||s.revision<0||!Array.isArray(s.entities)||!Array.isArray(s.changes)||s.changes.length!==s.revision)throw Error('Snapshot de programa inválido.');
        const live=new Map<string,number>();
        for(let n=0;n<s.changes.length;n++){
            const c=s.changes[n];if(!c||c.revision!==n+1||typeof c.reason!=='string'||!c.reason.trim()||![c.created,c.updated,c.deleted].every(Array.isArray))throw Error('Historial de revisiones inválido.');
            const touched=[...c.created,...c.updated,...c.deleted];
            if(!touched.length||new Set(touched).size!==touched.length||touched.some(id=>typeof id!=='string'||!id.startsWith(p.id+':')||!/^.*:(space|memory|instruction|function|data):[a-f0-9]{64}$/.test(id)))throw Error('Identidades del historial inválidas.');
            for(const id of c.created){if(live.has(id))throw Error('Creación duplicada en historial.');live.set(id,c.revision);}
            for(const id of c.updated){if(!live.has(id))throw Error('Actualización sin entidad.');live.set(id,c.revision);}
            for(const id of c.deleted){if(!live.delete(id))throw Error('Borrado sin entidad.');}
        }
        for(const item of s.entities){const e=copy(item);checkInput(e);if(e.id!==entityId(p.id,input(e))||p.#entities.has(e.id)||live.get(e.id)!==e.revision)throw Error('Identidad o revisión de entidad inválida.');p.#entities.set(e.id,e);}
        if(live.size!==p.#entities.size)throw Error('El historial no coincide con las entidades.');
        checkEntities(p.#entities,p.#descriptor);p.#revision=s.revision;p.#changes=copy(s.changes);return p;
    }
}
