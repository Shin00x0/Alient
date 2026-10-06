import {createImageProgram,recordAnalysis} from './program-adapter.ts';
import type {ProgramSnapshot} from '../core/program/types.ts';
import type {Program} from '../core/program/program.ts';
import {address} from '../core/program/address.ts';
import {mkdir,writeFile,readFile,rename} from 'node:fs/promises';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import type {Analysis,FunctionInfo,ListingInstruction,ListingManifest,CrossReference} from '../../types.ts';
import {loadImage,hex} from './loader.ts';
import {decodeArm64,type Operation} from './arm64.ts';
export const INTERNAL_VERSION='Internal TS 0.1';
/** Pure analysis entry point; never starts another process or executes the input. */
export function analyzeInternal(bytes:Buffer,name:string,previous?:ProgramSnapshot):{analysis:Analysis;rows:ListingInstruction[];program:Program} {
    const image=loadImage(bytes),rows:ListingInstruction[]=[],operations=new Map<string,Operation>();
    const executable=image.regions.filter(r=>r.code&&r.fileSize);
    if(!executable.length)throw Error('No se encontraron regiones de código en este binario.');
    const maxWords=100000;
    if(executable.reduce((n,r)=>n+Math.floor(r.fileSize/4),0)>maxWords)throw Error('Motor interno MVP: máximo 100000 palabras ARM64. Usa Ghidra para este archivo.');
    const program=createImageProgram(bytes,image);
    const entries=new Map<string,string>();
    const inside=(addr:bigint)=>executable.some(r=>addr>=r.address&&addr<r.address+BigInt(r.fileSize)&&(addr-r.address)%4n===0n);
    for(const s of image.symbols)if(s.function&&inside(s.address)&&!s.name.startsWith('$'))entries.set(hex(s.address),s.name);
    if(image.entry!==undefined&&inside(image.entry)&&!entries.has(hex(image.entry)))entries.set(hex(image.entry),'entry');
    for(const region of executable){
        if(region.address%4n)throw Error('Región ARM64 desalineada.');
        if(!entries.has(hex(region.address)))entries.set(hex(region.address),'region_'+hex(region.address));
        const sectionBytes=Buffer.from(program.readMemory(bytes,address('ram',region.address),region.fileSize));
        for(let offset=0;offset+4<=region.fileSize;offset+=4){
            const pc=region.address+BigInt(offset),address=hex(pc),op=decodeArm64(sectionBytes.readUInt32LE(offset),pc);
            if(operations.has(address))throw Error('Regiones ejecutables superpuestas: análisis interno no soportado.');
            operations.set(address,op);
            if(op.flow==='call'&&op.target!==undefined&&inside(op.target)&&!entries.has(hex(op.target)))entries.set(hex(op.target),'sub_'+hex(op.target));
            rows.push({address,offset:address,endOffset:hex(pc+3n),space:'ram',text:op.text,bytes:sectionBytes.subarray(offset,offset+4).toString('hex').match(/../g)!.join(' '),references:[]});
        }
    }
    rows.sort((a,b)=>BigInt('0x'+a.address)<BigInt('0x'+b.address)?-1:1);
    const starts=[...entries.keys()].sort((a,b)=>BigInt('0x'+a)<BigInt('0x'+b)?-1:1);
    const groups=new Map<string,ListingInstruction[]>();let index=0;
    for(const row of rows){while(index+1<starts.length&&BigInt('0x'+starts[index+1])<=BigInt('0x'+row.address))index++;const start=starts[index];if(start&&BigInt('0x'+start)<=BigInt('0x'+row.address)){row.functionAddress=start;row.function=entries.get(start);if(row.address===start)row.label=row.function;const group=groups.get(start)||[];group.push(row);groups.set(start,group);}}
    const allReferences:CrossReference[]=[],functions:FunctionInfo[]=[];
    for(const [start,instructions] of groups){
        const constants=new Map<number,bigint>();
        const branchTargets=new Set(instructions.flatMap(r=>{const op=operations.get(r.address)!;return op.target!==undefined?[hex(op.target)]:[];}));
        for(const row of instructions){
            const op=operations.get(row.address)!;
            if(branchTargets.has(row.address))constants.clear();
            let reference=op.reference;
            let constant=op.constant;
            if(op.addBase!==undefined&&op.addImmediate!==undefined&&constants.has(op.addBase)){constant=BigInt.asUintN(64,constants.get(op.addBase)!+op.addImmediate);reference=constant;}
            for(const r of op.invalidates||[])constants.delete(r);
            if(op.writes!==undefined){constants.delete(op.writes);if(constant!==undefined&&op.writes!==31)constants.set(op.writes,constant);}
            if(op.target!==undefined){row.references.push({to:hex(op.target),type:op.flow==='call'?'UNCONDITIONAL_CALL':op.flow==='conditional'?'CONDITIONAL_JUMP':'UNCONDITIONAL_JUMP'});}
            if(reference!==undefined&&image.regions.some(r=>reference!>=r.address&&reference!<r.address+BigInt(r.size)))row.references.push({to:hex(reference),type:'DATA'});
            for(const ref of row.references)allReferences.push({from:row.address,to:ref.to,type:ref.type,call:op.flow==='call',function:row.function,functionAddress:start});
            if(!op.known||op.flow)constants.clear();
        }
        const name=entries.get(start)!,unsupported=instructions.filter(r=>!operations.get(r.address)!.known).length;
        const lines:NonNullable<FunctionInfo['codeLines']>=[{indent:'',tokens:[{text:`// IR de registros ARM64 · ${name} · límites de función inferidos`,syntax:1}]}];
        lines.push({indent:'',tokens:[{text:'// No es C reconstruido: ABI, pila, tipos y efectos de llamadas pendientes.',syntax:1}]});
        for(const row of instructions)lines.push({indent:'',tokens:[{text:`${row.address}: ${operations.get(row.address)!.ir}`,syntax:8,address:row.address}]});
        const leaders=new Set([start]);
        for(let i=0;i<instructions.length;i++){const op=operations.get(instructions[i].address)!;if(op.target!==undefined&&op.flow!=='call')leaders.add(hex(op.target));if((op.flow||!op.known)&&instructions[i+1])leaders.add(instructions[i+1].address);}
        const flowBlocks:NonNullable<FunctionInfo['flowBlocks']>=[];
        for(let i=0;i<instructions.length;){const first=i;while(i+1<instructions.length&&!leaders.has(instructions[i+1].address))i++;const last=instructions[i],op=operations.get(last.address)!,edges:{to:string;type:string}[]=[];if(op.target!==undefined)edges.push({to:hex(op.target),type:op.flow==='call'?'CALL':'JUMP'});if(op.known&&!['return','jump','indirect'].includes(op.flow||'')&&instructions[i+1])edges.push({to:instructions[i+1].address,type:'FALL_THROUGH'});flowBlocks.push({address:instructions[first].address,end:last.address,edges});i++;}
        functions.push({address:start,name,signature:name+' (firma desconocida)',end:instructions.at(-1)!.endOffset,kind:'function',decompileStatus:'partial',warning:`IR experimental: ${unsupported} instrucciones sin semántica; sin reconstrucción de tipos ni control estructurado.`,code:lines.map(l=>l.indent+l.tokens.map(t=>t.text).join('')+'\n').join(''),codeLines:lines,error:'',instructions,instructionsTruncated:false,references:[],flowBlocks,variables:[]});
    }
    for(const f of functions)f.references=allReferences.filter(r=>r.to===f.address).map(r=>({from:r.from,type:r.type}));
    const strings:Analysis['strings']=[];let stringsTruncated=false;
    for(const region of image.regions.filter(r=>!r.code&&r.fileSize)){for(let i=0;i<region.fileSize&&strings.length<20000;){const start=i;while(i<region.fileSize&&(bytes[region.offset+i]>=32&&bytes[region.offset+i]<=126||[9,10,13].includes(bytes[region.offset+i])))i++;if(i-start>=4&&i<region.fileSize&&bytes[region.offset+i]===0)strings.push({address:hex(region.address+BigInt(start)),end:hex(region.address+BigInt(i)),value:bytes.toString('ascii',region.offset+start,region.offset+Math.min(i,start+4096))});i++;}if(strings.length>=20000)stringsTruncated=true;}
    const analysis:Analysis={engine:'internal',schemaVersion:4,engineVersion:INTERNAL_VERSION,name,format:image.format,language:image.architecture,imageBase:hex(image.imageBase),totalFunctions:functions.length,listingFunctions:functions.length,externalSymbols:image.symbols.filter(s=>s.external).length,totalInstructions:rows.length,limits:'Motor interno experimental: ARM64 parcial, límites de función inferidos y listing por palabras de secciones de código (pueden incluir datos). IR de registros, no decompilación C. Máximo 100000 palabras, 20000 cadenas ASCII de hasta 4096 caracteres.'+(stringsTruncated?' Cadenas truncadas.':''),blocks:image.regions.map(r=>({name:r.name,start:hex(r.address),size:String(r.size),permissions:r.permissions})),strings,functions,allReferences,symbols:image.symbols.map(s=>({name:s.name,address:hex(s.address),type:s.function?'Function':'Label',external:s.external,entry:!s.external&&image.entry===s.address})),types:[],bookmarks:[]};
    const recorded=recordAnalysis(program,analysis,rows,previous);
    return {rows,analysis,program:recorded};
}
export async function writeInternalAnalysis(bytes:Buffer,name:string,directory:string){
    let previous:ProgramSnapshot|undefined;
    // Reanalysis moves the old result to previous-result.json before starting the worker.
    let old:Analysis|undefined;
    for(const file of ['result.json','previous-result.json']){try{old=JSON.parse(await readFile(join(directory,file),'utf8'));break;}catch(e){if((e as NodeJS.ErrnoException).code!=='ENOENT')throw e;}}
    if(old?.program&&old.listingGeneration){if(!/^listing-[a-f0-9-]{36}$/.test(old.listingGeneration))throw Error('Generación anterior inválida.');previous=JSON.parse(await readFile(join(directory,old.listingGeneration,'program.json'),'utf8'));}
    const {analysis,rows,program}=analyzeInternal(bytes,name,previous),generation='listing-'+randomUUID(),folder=join(directory,generation);await mkdir(folder);
    const index:ListingManifest={generation,totalInstructions:rows.length,pageSize:256,defaultSpace:'ram',pages:[]};
    for(let offset=0;offset<rows.length;offset+=256){const page=rows.slice(offset,offset+256),n=index.pages.length;index.pages.push({page:n,space:'ram',start:page[0].offset,end:page.at(-1)!.endOffset,count:page.length});await writeFile(join(folder,n+'.json'),JSON.stringify(page));}
    await writeFile(join(folder,'index.json'),JSON.stringify(index));
    await writeFile(join(folder,'functions.json'),JSON.stringify(analysis.functions.map(f=>({address:f.address,name:f.name,qualifiedName:f.name,signature:f.signature}))));
    await writeFile(join(folder,'program.json'),JSON.stringify(program.snapshot()));
    analysis.listingGeneration=generation;
    await writeFile(join(directory,'result.json.tmp'),JSON.stringify(analysis));
    await rename(join(directory,'result.json.tmp'),join(directory,'result.json'));
}
