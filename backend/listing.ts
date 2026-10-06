import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import type {ListingPage,ListingManifest,ListingInstruction} from './types.ts';
const bad=(message:string,status=400)=>Object.assign(new Error(message),{status});
export async function readListingFunctions(directory:string,generation:string){
    if(!/^listing-[a-f0-9-]{36}$/.test(generation))throw bad('Regenera el análisis para generar el índice completo.',409);
    return JSON.parse(await readFile(join(directory,generation,'functions.json'),'utf8')) as {address:string;name:string;qualifiedName:string;signature:string}[];
}

export function locatePage(index:ListingManifest,input:string):{page:number;offset:bigint;space:string} {
    const match=input.match(/^(?:([\w.$-]+):)?(?:0x)?([a-f0-9]+)$/i);
    if(!match)throw bad('Dirección inválida. Usa hexadecimal, opcionalmente espacio:dirección.');
    const space=match[1]||index.defaultSpace,offset=BigInt('0x'+match[2]);
    const pages=index.pages.filter(p=>p.space===space);
    if(!pages.length)throw bad('Este espacio no contiene instrucciones analizadas.',404);
    let low=0,high=pages.length;
    while(low<high){const mid=(low+high)>>>1;if(BigInt('0x'+pages[mid].end)<offset)low=mid+1;else high=mid;}
    return {page:pages[Math.min(low,pages.length-1)].page,offset,space};
}
export async function readListing(directory:string,generation:string,params:URLSearchParams):Promise<ListingPage> {
    if(!/^listing-[a-f0-9-]{36}$/.test(generation))throw bad('Regenera el análisis para generar el listing completo.',409);
    const folder=join(directory,generation);
    const index:ListingManifest=JSON.parse(await readFile(join(folder,'index.json'),'utf8'));
    const target=params.get('address');
    const location=target?locatePage(index,target):undefined;
    const page=location?.page??Number(params.get('page')||0);
    if(!Number.isSafeInteger(page)||page<0||(page>=index.pages.length&&index.pages.length>0))throw bad('Página fuera del listing.');
    const rows:ListingInstruction[]=index.pages.length?JSON.parse(await readFile(join(folder,page+'.json'),'utf8')):[];
    let selected:string|undefined=rows[0]?.address;let exact=false;
    if(location){const match=rows.find(r=>BigInt('0x'+r.offset)<=location.offset&&BigInt('0x'+r.endOffset)>=location.offset);selected=(match||rows.find(r=>BigInt('0x'+r.offset)>=location.offset)||rows.at(-1))?.address;exact=!!match;}
    return {generation,page,totalPages:index.pages.length,totalInstructions:index.totalInstructions,rows,selected,exact,requested:target||undefined};
}
