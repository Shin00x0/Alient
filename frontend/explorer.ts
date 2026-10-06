import type {EngineCapabilities} from '../backend/engine/capabilities.js';
import type {Analysis,FunctionInfo,Project,CrossReference} from '../backend/types.js';

export function sameAddress(a:string,b:string):boolean {
    try {return BigInt('0x'+a.replace(/^0x/i,''))===BigInt('0x'+b.replace(/^0x/i,''));} catch {return a.toLowerCase()===b.toLowerCase();}
}
export function inRange(address:string,start:string,end=start):boolean {
    try {const a=BigInt('0x'+address.replace(/^0x/i,''));return a>=BigInt('0x'+start.replace(/^0x/i,''))&&a<=BigInt('0x'+end.replace(/^0x/i,''));}catch{return sameAddress(address,start);}
}
const referenceIndexes=new WeakMap<CrossReference[],{address:bigint;ref:CrossReference}[]>();
export function stringReferences(refs:CrossReference[],start:string,end=start):CrossReference[] {
    let low:bigint,high:bigint;
    try {low=BigInt('0x'+start.replace(/^0x/i,''));high=BigInt('0x'+end.replace(/^0x/i,''));}
    catch {return refs.filter(r=>sameAddress(r.to,start));}
    let index=referenceIndexes.get(refs);
    if(!index){index=[];for(const ref of refs){try{index.push({address:BigInt('0x'+ref.to.replace(/^0x/i,'')),ref});}catch{}}index.sort((a,b)=>a.address<b.address?-1:a.address>b.address?1:0);referenceIndexes.set(refs,index);}
    let left=0,right=index.length;
    while(left<right){const mid=(left+right)>>>1;if(index[mid].address<low)left=mid+1;else right=mid;}
    const found:CrossReference[]=[];
    while(left<index.length&&index[left].address<=high)found.push(index[left++].ref);
    return found;
}
export interface ExplorerContext {
    capabilities:EngineCapabilities; analysis:Analysis; selected?:FunctionInfo; project:Project; tab:string; query:string; cursor:string;
    xref?:{start:string;end:string};
    navigate:(address:string)=>void; showReferences:(start:string,end?:string)=>void;
    edit:(command:Record<string,unknown>)=>Promise<void>; message:(message:string,error?:boolean)=>void;
    searchBytes:(pattern:string)=>Promise<{offsets:number[];truncated:boolean}>; showHex:(offset:number)=>void;
}
const node=(tag:string,text?:string)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=text;return e;};
const button=(text:string,run:()=>void)=>{const b=node('button',text);b.onclick=run;return b;};
function grid(headers:string[],rows:(string|HTMLElement)[][]):HTMLElement {
    const table=node('table'),head=node('thead'),tr=node('tr'),body=node('tbody');
    headers.forEach(h=>tr.append(node('th',h)));head.append(tr);table.append(head,body);
    rows.slice(0,300).forEach(row=>{const tr=node('tr');row.forEach(value=>{const td=node('td');typeof value==='string'?td.textContent=value:td.append(value);tr.append(td);});body.append(tr);});
    const wrap=node('div');wrap.append(table);const info=node('div',`${rows.length} resultados${rows.length>300?' · Se muestran los primeros 300; acota la búsqueda.':''}`);info.className='help';wrap.prepend(info);return wrap;
}
function graph(nodes:{id:string;label:string}[],edges:{from:string;to:string;type:string}[],go:(address:string)=>void):SVGSVGElement {
    const ns='http://www.w3.org/2000/svg';
    const make=(tag:string,attrs:Record<string,string>)=>{const e=document.createElementNS(ns,tag);for(const [k,v]of Object.entries(attrs))e.setAttribute(k,v);return e;};
    const svg=make('svg',{viewBox:`0 0 900 ${Math.max(180,Math.ceil(nodes.length/2)*130+40)}`,role:'img','aria-label':'Grafo del programa','class':'flow-graph'}) as SVGSVGElement;
    const positions=new Map(nodes.map((n,i)=>[n.id,{x:60+(i%2)*440,y:30+Math.floor(i/2)*130}]));
    const defs=make('defs',{}),marker=make('marker',{id:'flow-arrow',viewBox:'0 0 10 10',refX:'9',refY:'5',markerWidth:'7',markerHeight:'7',orient:'auto-start-reverse'});marker.append(make('path',{d:'M 0 0 L 10 5 L 0 10 z',fill:'#77d3b5'}));defs.append(marker);svg.append(defs);
    for(const edge of edges){const a=positions.get(edge.from),b=positions.get(edge.to);if(!a||!b)continue;const path=make('path',{d:`M ${a.x+150} ${a.y+65} C ${a.x+150} ${a.y+110}, ${b.x-25} ${b.y-25}, ${b.x+150} ${b.y}`,fill:'none',stroke:'#77d3b5','stroke-width':'1.5','marker-end':'url(#flow-arrow)'});const title=make('title',{});title.textContent=edge.type;path.append(title);svg.append(path);}
    for(const n of nodes){const p=positions.get(n.id)!;const g=make('g',{tabindex:'0',role:'link','aria-label':n.label});g.append(make('rect',{x:String(p.x),y:String(p.y),width:'320',height:'65',rx:'5',fill:'#1b2838',stroke:'#5b8299'}));const title=make('title',{});title.textContent=n.label;g.append(title);const text=make('text',{x:String(p.x+12),y:String(p.y+24),fill:'#dce3ee','font-size':'13'});text.textContent=n.label.slice(0,38);g.append(text);const address=make('text',{x:String(p.x+12),y:String(p.y+47),fill:'#91bfcf','font-size':'12'});address.textContent=n.id;g.append(address);g.addEventListener('click',()=>go(n.id));g.addEventListener('keydown',e=>{if((e as KeyboardEvent).key==='Enter')go(n.id);});svg.append(g);}
    return svg;
}
export function renderExplorer(container:HTMLElement,c:ExplorerContext):boolean {
    const a=c.analysis,f=c.selected,q=c.query.toLowerCase(),refs=a.allReferences||[];
    const matches=(...parts:unknown[])=>parts.join(' ').toLowerCase().includes(q);
    const address=(value:string)=>button(value,()=>c.navigate(value));
    const xref=(value:string,end?:string)=>button('XREF',()=>c.showReferences(value,end));
    if(c.tab==='strings') {
        container.append(grid(['Dirección','Cadena','Referencias'],a.strings.filter(s=>matches(s.address,s.value)).map(s=>{const hits=stringReferences(refs,s.address,s.end);return [address(s.address),s.value,button(`${hits.length} XREF`,()=>c.showReferences(s.address,s.end))];})));return true;
    }
    if(c.tab==='xref'||c.tab==='refs') {
        const target=c.tab==='xref'?c.xref:{start:f?.address||'',end:f?.address||''};
        if(!target){container.append(node('p','Selecciona una dirección o cadena.'));return true;}
        const inbound=stringReferences(refs,target.start,target.end),outbound=refs.filter(r=>c.tab==='refs'&&f?f.instructions.some(i=>sameAddress(i.address,r.from)):inRange(r.from,target.start,target.end));
        container.append(node('p',`Referencias de ${target.start}${target.end!==target.start?' — '+target.end:''}`));
        container.append(grid(['Dirección','Desde','Hacia','Tipo','Función'],[...inbound.map(r=>({r,d:'Entrante'})),...outbound.map(r=>({r,d:'Saliente'}))].filter(({r})=>matches(r.from,r.to,r.type,r.function)).map(({r,d})=>[d,address(r.from),address(r.to),r.type,r.function||'—'])));
        if(a.referencesTruncated)container.prepend(node('p','Índice de referencias limitado a 100 000 entradas.'));return true;
    }
    if(c.tab==='symbols'||c.tab==='imports'||c.tab==='exports') {
        container.append(grid(['Símbolo','Dirección','Tipo','Referencias'],(a.symbols||[]).filter(s=>(c.tab!=='imports'||s.external)&&(c.tab!=='exports'||s.entry)&&matches(s.name,s.address,s.type)).map(s=>[s.name,address(s.address),s.type,xref(s.address)])));return true;
    }
    if(c.tab==='types') {container.append(grid(['Tipo','Ruta (para editar variables)','Bytes'],(a.types||[]).filter(t=>matches(t.name,t.path)).map(t=>[t.name,t.path,String(t.size)])));return true;}
    if(c.tab==='bookmarks'){container.append(grid(['Dirección','Tipo','Categoría','Comentario'],(a.bookmarks||[]).filter(b=>matches(b.address,b.type,b.category,b.comment)).map(b=>[address(b.address),b.type,b.category,b.comment])));return true;}
    if(c.tab==='variables'){container.append(grid(['Variable','Tipo','Almacenamiento','Clase'],(f?.variables||[]).filter(v=>matches(v.name,v.type,v.storage)).map(v=>[v.name,v.type,v.storage,v.parameter?'Parámetro':'Local'])));return true;}
    if(c.tab==='instructions'){container.append(grid(['Dirección','Función','Instrucción','Comentario'],a.functions.flatMap(fn=>fn.instructions.filter(i=>matches(i.address,i.text,i.bytes,i.comment,fn.name)).map(i=>[address(i.address),fn.name,i.text,i.comment||'']))));return true;}
    if(c.tab==='code-search'&&c.project.engine==='internal'){
        const form=node('form') as HTMLFormElement;form.className='edit-form';
        const input=node('input') as HTMLInputElement;input.value=c.query;input.setAttribute('aria-label','Consulta global');input.placeholder='Palabras completas: función, instrucción, C o cadena';
        const submit=node('button','Buscar en todo el programa') as HTMLButtonElement;
        const results=node('div');form.append(input,submit);
        let offset=0;
        const search=async()=>{submit.disabled=true;try{
            const response=await fetch('/api/projects/'+c.project.id+'/native-search?q='+encodeURIComponent(input.value)+'&offset='+offset);
            const r=await response.json();if(!response.ok)throw Error(r.error);
            results.replaceChildren(node('p',`${r.total} coincidencias · desde ${offset+1}`),grid(['Clase','Dirección','Texto'],r.results.map((d:{kind:string;address:string;text:string})=>[d.kind,address(d.address),d.text])));
            if(offset>0)results.append(button('Anterior',()=>{offset=Math.max(0,offset-100);void search();}));
            if(offset+100<r.total)results.append(button('Siguiente',()=>{offset+=100;void search();}));
        }catch(e){c.message(String(e),true);}finally{submit.disabled=false;}};
        form.onsubmit=e=>{e.preventDefault();offset=0;void search();};container.append(node('p','Índice persistente del motor Rust; búsqueda por palabras, sin distinguir mayúsculas.'),form,results);return true;
    }
    if(c.tab==='code-search'){container.append(grid(['Función','Línea','Pseudocódigo'],q?a.functions.flatMap(fn=>fn.code.split('\n').flatMap((line,index)=>matches(line)?[[button(fn.name,()=>{c.navigate(fn.address);const codeLine=document.querySelector('#code .decomp-line[data-line="'+(index+1)+'"]');codeLine?.classList.add('current-code-line');codeLine?.scrollIntoView({block:'nearest'});}),String(index+1),line]]:[])):[]));return true;}
    if(c.tab==='calls'){const calls=refs.filter(r=>r.call&&(!f||r.functionAddress===f.address||sameAddress(r.to,f.address))).filter(r=>matches(r.function,r.to,r.from));container.append(grid(['Llamador','Instrucción','Destino'],calls.map(r=>[r.function||'—',address(r.from),address(r.to)])));const names=new Map(a.functions.map(fn=>[fn.address,fn.name]));const ids=[...new Set(calls.flatMap(r=>[r.functionAddress||r.from,r.to]))].slice(0,100);container.append(graph(ids.map(id=>({id,label:names.get(id)||id})),calls.map(r=>({from:r.functionAddress||r.from,to:r.to,type:r.type})),c.navigate));return true;}
    if(c.tab==='bytesearch') {
        const form=node('form') as HTMLFormElement;form.className='edit-form';const label=node('label','Patrón hexadecimal (?? = cualquier byte)'),input=node('input') as HTMLInputElement;input.placeholder='48 8b ?? ??';label.append(input);const submit=node('button','Buscar bytes') as HTMLButtonElement;form.append(label,submit);const results=node('div');
        form.onsubmit=e=>{e.preventDefault();submit.disabled=true;void c.searchBytes(input.value).then(r=>{results.replaceChildren(grid(['Offset de archivo'],r.offsets.map(o=>[button('0x'+o.toString(16),()=>c.showHex(o))])));if(r.truncated)results.prepend(node('p','Más de 200 coincidencias; acota el patrón.'));}).catch(e=>c.message(e.message,true)).finally(()=>submit.disabled=false);};container.append(form,results);return true;
    }
    if(c.tab==='edit') {
        if(!c.capabilities.actions.edit.enabled){container.append(node('p',c.capabilities.actions.edit.reason));return true;}
        if(!c.project.persistent){container.append(node('p','Regenera el análisis una vez para habilitar la edición del proyecto Ghidra.'));return true;}
        const form=node('form') as HTMLFormElement;form.className='edit-form';
        const select=node('select') as HTMLSelectElement;
        for(const [value,text] of [['rename','Renombrar función / símbolo'],['comment','Comentario de instrucción'],['function-comment','Comentario de función'],['signature','Firma C de función'],['variable','Renombrar / cambiar tipo de variable'],['bookmark','Añadir marcador'],['define-data','Definir datos con tipo'],['clear-data','Quitar datos definidos'],['create-function','Crear función'],['delete-function','Quitar función'],['define-type','Definir tipo (JSON)'],['jump-table','Tabla de salto absoluta (JSON)'],['undo','Deshacer'],['redo','Rehacer']]){if(!c.capabilities.editOperations.includes(value))continue;const option=node('option',text) as HTMLOptionElement;option.value=value;select.append(option);}
        const addr=node('input') as HTMLInputElement;addr.value=c.cursor||f?.address||'';
        const value=node('textarea') as HTMLTextAreaElement;value.maxLength=8000;value.placeholder='Nuevo nombre, comentario o firma C según la operación';
        const variable=node('select') as HTMLSelectElement;for(const v of f?.variables||[]){const option=node('option',`${v.name} · ${v.type} · ${v.storage}`) as HTMLOptionElement;option.value=v.id;variable.append(option);}
        const type=node('input') as HTMLInputElement;type.placeholder=c.project.engine==='internal'?'uint32_t (tipo existente)':'/int (ruta del panel Tipos)';
        for(const [text,control] of [['Operación',select],['Dirección virtual',addr],['Nuevo valor',value],['Variable (solo operación de variable)',variable],['Tipo (variable o definición de datos)',type]] as const){const label=node('label',text);control.setAttribute('aria-label',text);label.append(control);form.append(label);}
        select.onchange=()=>{
            const noAddress=['undo','redo','define-type'].includes(select.value);addr.disabled=noAddress;
            type.disabled=!['variable','define-data'].includes(select.value);variable.disabled=select.value!=='variable';
            value.disabled=['undo','redo','create-function','delete-function','clear-data','define-data'].includes(select.value);
            if(['signature','variable','function-comment'].includes(select.value))addr.value=f?.address||'';value.value=select.value==='signature'?f?.decompiledSignature||f?.signature||'':select.value==='function-comment'?f?.comment||'':select.value==='define-type'?JSON.stringify({name:'Pair',ty:{Struct:{size:8,fields:[{name:'x',ty:'uint32_t',offset:0},{name:'y',ty:'uint32_t',offset:4}]} }},null,2):select.value==='jump-table'?JSON.stringify({base:'400100',count:2,index:'rax'},null,2):'';};
        const submit=node('button','Aplicar y actualizar pseudocódigo') as HTMLButtonElement;form.append(submit);
        form.onsubmit=e=>{e.preventDefault();
            let command:Record<string,unknown>={operation:select.value,address:addr.value.replace(/^0x/i,''),value:value.value,variableId:variable.value,dataType:type.value};
            try {
                if(select.value==='define-data')command.ty=type.value;
                if(select.value==='define-type'||select.value==='jump-table'){const fields=JSON.parse(value.value);command={...command,...fields,operation:select.value};}
            }catch{c.message('JSON inválido en Nuevo valor.',true);return;}
            submit.disabled=true;void c.edit(command).catch(e=>c.message(e.message,true)).finally(()=>submit.disabled=false);
        };
        container.append(node('p','Cambios reales del programa. Se conservan al reabrir y regenerar el proyecto.'),form);return true;
    }
    return false;
}
