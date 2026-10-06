import {tabCapability,renderCapabilities} from './capabilities-view.js';
import type {EngineCapabilities} from '../backend/engine/capabilities.js';
import { ListingView } from './listing-view.js';
import { renderExplorer, sameAddress, inRange } from './explorer.js';
import { renderCode } from './code-view.js';
import type { Analysis, FunctionInfo, Project, ListingInstruction } from '../backend/types.js';
const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
let project: Project | undefined, analysis: Analysis | undefined, selected: FunctionInfo | undefined, tab = 'strings', hexOffset = 0, openVersion = 0;
let capabilities:EngineCapabilities|undefined;
let disposeCfgGraph: (() => void) | undefined;
let detailsVersion = 0;
const detailsDialog = $<HTMLDialogElement>('details-dialog');
function openDetails() {
    if (!detailsDialog.open) detailsDialog.showModal();
    syncTabs();
}
function closeDetails() { detailsDialog.close(); }
$('details-close').onclick = closeDetails;
detailsDialog.addEventListener('click', event => { if(event.target===detailsDialog){const r=detailsDialog.getBoundingClientRect();if(event.clientX<r.left||event.clientX>r.right||event.clientY<r.top||event.clientY>r.bottom)closeDetails();} });
detailsDialog.addEventListener('close', () => { detailsVersion++; disposeCfgGraph?.(); disposeCfgGraph=undefined; syncTabs(); });
function navigateFromDetails(address: string) { closeDetails(); navigate(address); }

let inlineGraph = false;
let graphVersion = 0;
let disposeInlineGraph: (() => void) | undefined;
function closeListingGraph() {
    inlineGraph = false; graphVersion++; disposeInlineGraph?.(); disposeInlineGraph = undefined;
    $('listing-graph').replaceChildren(); $('listing-graph').hidden = true;
    $('listing').hidden = false; $('listing-controls').hidden = false;
    $('listing').focus({preventScroll:true});
}
async function updateListingGraph() {
    if (!inlineGraph || !selected) return;
    const version = ++graphVersion, fn = selected;
    disposeInlineGraph?.(); disposeInlineGraph = undefined;
    const host = $('listing-graph');
    host.replaceChildren(el('p', 'Cargando grafo…'));
    try {
        const {renderCfgGraph} = await import('./cfg-graph.js');
        if (version !== graphVersion || !inlineGraph) return;
        const back = el('button', 'Volver al listing · Espacio'); back.onclick = closeListingGraph;
        const body = el('div', undefined, 'listing-graph-body'); host.replaceChildren(back, body);
        disposeInlineGraph = renderCfgGraph(body, fn, address => { closeListingGraph(); navigate(address); }, cursor);
    } catch (error) {
        if (version !== graphVersion) return;
        closeListingGraph(); notice('No se pudo abrir el grafo: ' + String(error), true);
    }
}
$('listing-graph').addEventListener('keydown', event => {
    if ((event.key === ' ' || event.key === 'Escape') && !event.repeat && !(event.target instanceof HTMLButtonElement)) {
        event.preventDefault(); closeListingGraph();
    }
});
let fullFunctions:{address:string;name:string;qualifiedName:string;signature:string}[]=[];
let cursor='', xrefTarget:{start:string;end:string}|undefined, history:string[]=[], historyIndex=-1;
const listingView=new ListingView($('listing'),$('listing-controls'),selectListingInstruction,navigate,message=>notice(message),row=>{void showFlowForListing(row);} );
const statusNames: Record<string, string> = { queued: 'En cola', analyzing: 'Analizando…', ready: 'Completado', failed: 'Error', cancelled: 'Cancelado' };
function notice(message: string, error = false) { $('notice').hidden = !message; $('notice').textContent = message; $('notice').classList.toggle('error', error); }
async function api<T>(path: string, options?: RequestInit): Promise<T> { const response = await fetch('/api/' + path, options); const data = await response.json(); if (!response.ok)
    throw Error(data.error || 'Error de servidor'); return data; }
function el(tag: string, text?: string, className?: string) { const node = document.createElement(tag); if (text !== undefined)
    node.textContent = text; if (className)
    node.className = className; return node; }
function safe(action: () => Promise<void>) { return () => { void action().catch(e => notice(e.message, true)); }; }
async function refresh() { const health = await api<{
    engine: string;
    selectedEngine: string;
    message: string;
}>('health'); $<HTMLSelectElement>('engine-select').value=health.selectedEngine; $('engine').textContent = health.engine === 'ready' ? '● Motor conectado' : '○ Motor no configurado'; $('engine').title = health.message; const all = await api<Project[]>('projects'); $('project-count').textContent = String(all.length); $('projects').replaceChildren(); if (!all.length)
    $('projects').append(el('div', 'Todavía no hay proyectos.', 'help')); for (const p of all) {
    const b = el('button', p.name, p.id === project?.id ? 'selected' : '');
    b.append(el('small', statusNames[p.status]+' · '+(p.engine==='internal'?'Interno':'Ghidra')));
    b.onclick = safe(() => openProject(p.id));
    $('projects').append(b);
} }
async function openProject(id: string) { if(inlineGraph)closeListingGraph(); const previousAddress=project?.id===id?selected?.address:undefined; if(project?.id!==id){history=[];historyIndex=-1;cursor='';xrefTarget=undefined;} const version = ++openVersion; const p = await api<Project>('projects/' + id); if (version !== openVersion)
    return; const caps=await api<EngineCapabilities>('projects/'+id+'/capabilities');if(version!==openVersion)return;capabilities=caps; listingView.reset(p.id); fullFunctions=[]; project = p; analysis = undefined; selected = undefined; hexOffset = 0; $('filename').textContent = p.name; $('architecture').textContent = '—'; $('overview').replaceChildren(); $('listing').replaceChildren(el('div', 'Esperando resultados del análisis.', 'empty')); $('code').textContent = 'El pseudocódigo aparecerá al completar el análisis.'; $('signature').textContent = 'Selecciona una función'; $('decompile-status').textContent = p.engine==='internal'?'Motor interno':'Motor Ghidra'; $('code-title').textContent=p.engine==='internal'?'DECOMPILER RUST':'DECOMPILER'; $('code-kind').textContent=p.engine==='internal'?'C parcial / IR nativa':'C / pseudocódigo'; $('copy-code').textContent=p.engine==='internal'?'Copiar C':'Copiar C'; $('export').toggleAttribute('disabled', true); $('copy-code').toggleAttribute('disabled', true); $('reanalyze').toggleAttribute('disabled', !caps.actions.analyze.enabled);$('reanalyze').title=caps.actions.analyze.reason;applyCapabilities(); renderFunctions(); await renderDetails(); if (p.status === 'ready') {
    const result = await api<Analysis>('projects/' + id + '/result');
    if (version !== openVersion)
        return;
    analysis = result;
    if(result.listingGeneration){fullFunctions=await api('projects/'+id+'/listing-functions');if(version!==openVersion)return;}
    $('architecture').textContent = result.language+' · '+(p.engine==='internal'?'Motor interno':'Ghidra');
    for (const [label, value] of [['Formato', result.format], ['Base', '0x' + result.imageBase], ['Funciones', `${result.functions.length} / ${result.listingFunctions ?? result.totalFunctions} · ${result.externalSymbols ?? 0} símbolos externos`]]) {
        const span = el('span', label);
        span.append(el('b', value));
        $('overview').append(span);
    }
    $('export').removeAttribute('disabled');
    renderFunctions();
    if (result.functions.length)
        selectFunction(result.functions.find(f=>f.address===previousAddress)||result.functions.find(f=>f.name==='main')||result.functions[0]);
    else {
        void listingView.page(0);
        $('code').textContent = 'No hay funciones decompilables.';
        await renderDetails();
    }
    notice(p.error || result.limits, !!p.error);
}
else {
    notice(p.error || statusNames[p.status], p.status === 'failed');
} $('status').textContent = `${statusNames[p.status]} · ${(p.size / 1024).toFixed(1)} KiB`; await refresh(); }
function renderFunctions() { const q = $<HTMLInputElement>('search').value.toLowerCase(); $('functions').replaceChildren(); const functions = (fullFunctions.length?fullFunctions:analysis?.functions||[]).filter(f => `${f.name} ${f.address} ${project?.annotations[f.address]?.label || ''}`.toLowerCase().includes(q)) || []; $('function-count').textContent = String(functions.length); for (const f of functions) {
    const b = el('button', project?.annotations[f.address]?.label || f.name, f.address === selected?.address ? 'selected' : '');
    b.append(el('small', f.address + ((f as FunctionInfo).kind === 'external' ? ' · Importada' : (f as FunctionInfo).kind === 'thunk' ? ' · Thunk' : '')));
    b.onclick = () => navigate(f.address);
    $('functions').append(b);
} }
function selectFunction(f: FunctionInfo, loadListing=true) { selected=f; cursor=f.address; $<HTMLInputElement>('goto').value=cursor; $('signature').textContent=f.decompiledSignature||f.signature; if(loadListing)void listingView.address(f.address); renderCode($('code'), f, navigate); $('copy-code').toggleAttribute('disabled', !f.code); $('code').classList.remove('empty'); $('decompile-status').textContent = f.decompileStatus === 'external' ? 'Importación · implementación no incluida' : f.decompileStatus === 'no-instructions' ? 'Sin instrucciones' : f.error ? 'Decompilación incompleta' : f.warning ? (project?.engine==='internal'?'Interno: ':'Ghidra: ') + f.warning : `${f.name} · ${project?.engine==='internal'?'':'Ghidra '}${analysis?.engineVersion || 'exportación anterior'} · ${f.address}`; renderFunctions(); void renderDetails().catch(e => notice(e.message, true)); }
function table(headers: string[], rows: (string | HTMLElement)[][]) { const t = el('table'), head = el('tr'); for (const h of headers)
    head.append(el('th', h)); const thead = el('thead'); thead.append(head); t.append(thead); const body = el('tbody'); for (const row of rows) {
    const tr = el('tr');
    for (const cell of row) {
        const td = el('td');
        if (typeof cell === 'string')
            td.textContent = cell;
        else
            td.append(cell);
        tr.append(td);
    }
    body.append(tr);
} t.append(body); return t; }
async function renderDetails() {
    if(inlineGraph)void updateListingGraph();
    if (!detailsDialog.open) return;
    const version = ++detailsVersion;
    disposeCfgGraph?.();
    disposeCfgGraph = undefined;
    const container = $('details');
    container.replaceChildren();
    if (!project) {
        container.append(el('div', 'Abre un proyecto para explorar sus resultados.', 'help'));
        return;
    }
    const p = project;
    if(capabilities&&tab==='capabilities'){renderCapabilities(container,capabilities);return;}
    if(capabilities){const access=tabCapability(tab,capabilities);if(!access.enabled){container.append(el('p',access.reason));return;}}
    if (tab === 'log') {
        container.append(el('pre', p.log || 'Sin mensajes.', 'log'));
        if (['queued', 'analyzing'].includes(p.status)) {
            const cancel = el('button', 'Cancelar análisis');
            cancel.onclick = safe(async () => { await api('projects/' + p.id + '/cancel', { method: 'POST' }); await openProject(p.id); });
            container.prepend(cancel);
        }
        return;
    }
    if (tab === 'hex') {
        const data = await api<{
            offset: number;
            total: number;
            bytes: number[];
        }>('projects/' + p.id + '/bytes?offset=' + hexOffset);
        if (project?.id !== p.id || tab !== 'hex')
            return;
        const controls = el('div', undefined, 'hexbar');
        for (const [name, delta] of [['← Anterior', -256], ['Siguiente →', 256]] as const) {
            const b = el('button', name) as HTMLButtonElement;
            b.disabled = delta < 0 ? hexOffset === 0 : hexOffset + 256 >= data.total;
            b.onclick = safe(async () => { hexOffset += delta; await renderDetails(); });
            controls.append(b);
        }
        controls.append(el('span', `Offset de archivo 0x${hexOffset.toString(16)} · ${data.total} bytes`));
        container.append(controls);
        let text = '';
        for (let i = 0; i < data.bytes.length; i += 16) {
            const row = data.bytes.slice(i, i + 16);
            text += (hexOffset + i).toString(16).padStart(8, '0') + '  ' + row.map(b => b.toString(16).padStart(2, '0')).join(' ').padEnd(47) + '  ' + row.map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('') + '\n';
        }
        container.append(el('pre', text, 'hex'));
        return;
    }
    if (!analysis) {
        container.append(el('div', 'Resultados pendientes. El registro muestra el progreso del motor.', 'help'));
        return;
    }
    if (tab === 'flow') {
        if (!selected) { container.append(el('p', 'Selecciona una función para ver su flujo de control.')); return; }
        const fn = selected;
        container.append(el('p', 'Cargando grafo…'));
        try {
            const { renderCfgGraph } = await import('./cfg-graph.js');
            if (version !== detailsVersion) return;
            container.replaceChildren();
            disposeCfgGraph = renderCfgGraph(container, fn, navigateFromDetails, cursor);
        } catch (error) {
            if (version !== detailsVersion) return;
            container.replaceChildren(el('p', 'No se pudo cargar el grafo: ' + (error instanceof Error ? error.message : String(error))));
        }
        return;
    }
    if(renderExplorer(container,{analysis,selected,project:p,capabilities:capabilities!,tab,query:$<HTMLInputElement>('detail-search').value,cursor,xref:xrefTarget,navigate:navigateFromDetails,showReferences,edit:async command=>{await api('projects/'+p.id+'/edit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(command)});tab='log';syncTabs();await openProject(p.id);},message:notice,searchBytes:pattern=>api('projects/'+p.id+'/byte-search?pattern='+encodeURIComponent(pattern)),showHex:offset=>{hexOffset=Math.floor(offset/256)*256;tab='hex';syncTabs();void renderDetails();}})) return;
    if (tab === 'strings')
        container.append(table(['Dirección', 'Cadena'], analysis.strings.map(s => [s.address, s.value])));
    if (tab === 'memory')
        container.append(table(['Bloque', 'Inicio', 'Bytes', 'Permisos'], analysis.blocks.map(b => [b.name, b.start, b.size, b.permissions])));
    if (tab === 'refs') {
        const rows = selected?.references.map(r => { const button = el('button', r.from); button.onclick = () => { const owner = analysis?.functions.find(f => f.instructions.some(i => i.address === r.from)); if (owner)
            selectFunction(owner);
        else
            notice('La función de origen no está incluida en esta exportación.'); }; return [button, r.type]; }) || [];
        container.append(rows.length ? table(['Desde', 'Tipo'], rows) : el('div', 'Sin referencias entrantes para esta función.', 'help'));
    }
    if (tab === 'notes') {
        if (!selected) {
            container.append(el('div', 'Selecciona una función.', 'help'));
            return;
        }
        const f = selected;
        container.append(el('div', 'Etiquetas y comentarios del proyecto web. No modifican los símbolos ni el pseudocódigo del motor.', 'help'));
        const form = el('form', undefined, 'note-form') as HTMLFormElement;
        const label = el('input') as HTMLInputElement;
        label.maxLength = 200;
        label.value = p.annotations[f.address]?.label || '';
        const comment = el('textarea') as HTMLTextAreaElement;
        comment.maxLength = 8000;
        comment.value = p.annotations[f.address]?.comment || '';
        const a = el('label', 'Etiqueta de función');
        a.append(label);
        const b = el('label', 'Comentario');
        b.append(comment);
        const submit = el('button', 'Guardar anotación') as HTMLButtonElement;
        submit.type = 'submit';
        form.append(a, b, submit);
        form.onsubmit = e => { e.preventDefault(); submit.disabled = true; void api<Project>('projects/' + p.id + '/annotations', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ address: f.address, label: label.value, comment: comment.value }) }).then(updated => { if (project?.id === p.id) {
            project = updated;
            renderFunctions();
        } notice('Anotación guardada.'); }).catch(e => notice(e.message, true)).finally(() => submit.disabled = false); };
        container.append(form);
    }
}
$<HTMLInputElement>('search').oninput = renderFunctions;
$('refresh').onclick = safe(refresh);
$<HTMLInputElement>('upload').onchange = () => { const input = $<HTMLInputElement>('upload'), file = input.files?.[0]; if (!file)
    return; input.disabled = true; void (async () => { notice('Importando ' + file.name + '…'); if (file.size > 32 * 1024 * 1024)
    throw Error('Máximo 32 MiB por archivo.'); const p = await api<Project>('projects?name=' + encodeURIComponent(file.name), { method: 'POST', body: file }); tab = 'log'; syncTabs(); await openProject(p.id); })().catch(e => notice(e.message, true)).finally(() => { input.disabled = false; input.value = ''; }); };
function syncTabs() {
    document.querySelectorAll<HTMLButtonElement>('[data-tab]').forEach(b => {
        const active = detailsDialog.open && b.dataset.tab === tab;
        b.setAttribute('aria-selected', String(active));
        b.setAttribute('aria-haspopup', 'dialog');
        b.setAttribute('aria-controls', 'details-dialog');
        if (b.dataset.tab === tab) $('details-title').textContent = b.textContent;
    });
}
document.querySelectorAll<HTMLButtonElement>('[data-tab]').forEach(b => b.onclick = safe(async () => { tab = b.dataset.tab!; if(tab==='xref')xrefTarget={start:cursor||selected?.address||'',end:cursor||selected?.address||''}; openDetails(); await renderDetails(); }));
$('export').onclick = () => { if (!analysis || !project)
    return; const blob = new Blob([JSON.stringify({ project, analysis }, null, 2)], { type: 'application/json' }), url = URL.createObjectURL(blob), a = el('a') as HTMLAnchorElement; a.href = url; a.download = project.name + '.analysis.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); };
let polling = false;
setInterval(() => { if (polling || !project || !['queued', 'analyzing'].includes(project.status))
    return; polling = true; const id = project.id; void api<Project>('projects/' + id).then(async (p) => { if (project?.id !== id)
    return; if (p.status !== project.status) {
    await openProject(id);
    return;
} project = p; if (tab === 'log')
    await renderDetails(); }).catch(e => notice(e.message, true)).finally(() => polling = false); }, 2000);
void (async () => { await refresh(); const all = await api<Project[]>('projects'); const initial = all.find(p => p.status === 'ready') || all[0]; if (initial)
    await openProject(initial.id); })().catch(e => notice(e.message, true));

$('reanalyze').onclick = safe(async () => { if (!project) return; const id = project.id; await api('projects/' + id + '/reanalyze', {method:'POST'}); tab = 'log'; syncTabs(); await openProject(id); });
$('copy-code').onclick = safe(async () => { if (!selected?.code) return; await navigator.clipboard.writeText(selected.code); notice(project?.engine==='internal'?'Pseudocódigo del motor Rust copiado.':'Pseudocódigo original de Ghidra copiado.'); });

function showReferences(start:string,end=start){xrefTarget={start,end};tab='xref';$<HTMLInputElement>('detail-search').value='';openDetails();void renderDetails().catch(e=>notice(e.message,true));}
function navigate(input:string,record=true){
    if(!analysis)return;
    const byName=fullFunctions.find(f=>f.name===input||f.qualifiedName===input)||analysis.functions.find(f=>f.name===input);
    const address=byName?.address||input.trim().replace(/^0x/i,'');
    if(!byName&&!/^(?:[\w.$-]+:)?[a-fA-F0-9]+$/.test(address)){notice('Dirección hexadecimal o función inválida.',true);return;}
    const string=analysis.strings.find(s=>inRange(address,s.address,s.end));
    if(string){showReferences(string.address,string.end);notice('Cadena: '+string.value);}
    void listingView.address(address);
    cursor=address;$<HTMLInputElement>('goto').value=address;
    if(record&&history[historyIndex]!==address){history=history.slice(0,historyIndex+1);history.push(address);historyIndex=history.length-1;}
    $<HTMLButtonElement>('back').disabled=historyIndex<=0;$<HTMLButtonElement>('forward').disabled=historyIndex>=history.length-1;
}
let listingFunctionAddress: string | undefined;
const functionRequests=new Map<string,Promise<FunctionInfo>>();
async function loadListingFunction(address:string){
    if(!project||!analysis)return;
    const version=openVersion, snapshot=analysis, id=project.id, key=`${id}/${snapshot.listingGeneration}/${address}`;
    let request=functionRequests.get(key);
    if(!request){request=api<FunctionInfo>('projects/'+id+'/decompile?address='+encodeURIComponent(address));functionRequests.set(key,request);}
    try {
        const f=await request;
        if(version!==openVersion||analysis!==snapshot)return;
        if(!snapshot.functions.some(item=>item.address===f.address))snapshot.functions.push(f);
        if(listingFunctionAddress!==address)return;
        const instruction=cursor;
        selectFunction(f,false);
        cursor=instruction;$<HTMLInputElement>('goto').value=cursor;highlightCode(cursor);
    } catch(e){
        if(version!==openVersion||listingFunctionAddress!==address)return;
        $('decompile-status').textContent='Decompilación pendiente';
        const retry=el('button','Reintentar decompilación');
        retry.onclick=()=>{retry.remove();void loadListingFunction(address);};
        $('code').replaceChildren(el('p',e instanceof Error?e.message:String(e)),retry);
    } finally {if(functionRequests.get(key)===request)functionRequests.delete(key);}
}
async function showFlowForListing(row: ListingInstruction) {
    if (!row.functionAddress) { notice('La instrucción seleccionada no pertenece a una función con CFG.', true); return; }
    const version = openVersion;
    const known = analysis?.functions.find(fn => fn.address === row.functionAddress);
    if (known) selectFunction(known, false);
    else { listingFunctionAddress = row.functionAddress; await loadListingFunction(row.functionAddress); }
    if (version !== openVersion || !selected || selected.address !== row.functionAddress) return;
    cursor = row.address; $<HTMLInputElement>('goto').value = cursor;
    if (!selected.flowBlocks?.length) { notice('Esta función no incluye bloques básicos para mostrar.', true); return; }
    inlineGraph = true; $('listing').hidden = true; $('listing-controls').hidden = true;
    $('listing-graph').hidden = false; $('listing-graph').focus({preventScroll:true});
    await updateListingGraph();
}
function selectListingInstruction(row:ListingInstruction){
    listingFunctionAddress=row.functionAddress;
    const fn=analysis?.functions.find(f=>f.address===row.functionAddress);
    if(fn&&selected?.address!==fn.address)selectFunction(fn,false);
    if(!fn){selected=undefined;renderFunctions();$('code').textContent=row.function?'Decompilando esta función con Ghidra…':'Instrucción fuera de las funciones exportadas; no hay pseudocódigo asociado en esta vista.';$('copy-code').toggleAttribute('disabled',true);$('decompile-status').textContent='Listing completo · pseudocódigo no disponible';void renderDetails().catch(e=>notice(e.message,true));}
    if(!fn&&row.functionAddress)void loadListingFunction(row.functionAddress);
    cursor=row.address;$<HTMLInputElement>('goto').value=cursor;$('signature').textContent=row.function?`${row.function} · ${row.address}`:`${row.space} · ${row.address}`;highlightCode(cursor);
}
$<HTMLFormElement>('goto-form').onsubmit=e=>{e.preventDefault();navigate($<HTMLInputElement>('goto').value);};
$('back').onclick=()=>{if(historyIndex>0)navigate(history[--historyIndex],false);};
$('forward').onclick=()=>{if(historyIndex<history.length-1)navigate(history[++historyIndex],false);};
$('cursor-xref').onclick=()=>{if(cursor)showReferences(cursor);};
$('detail-search').oninput=()=>{void renderDetails().catch(e=>notice(e.message,true));};
document.addEventListener('keydown',e=>{if(e.target instanceof HTMLInputElement||e.target instanceof HTMLTextAreaElement||e.target instanceof HTMLSelectElement)return;if(e.key.toLowerCase()==='g'){e.preventDefault();$('goto').focus();}if(e.key.toLowerCase()==='x'&&cursor){e.preventDefault();showReferences(cursor);}if(e.altKey&&e.key==='ArrowLeft'){e.preventDefault();$('back').click();}if(e.altKey&&e.key==='ArrowRight'){e.preventDefault();$('forward').click();}});

function highlightCode(address:string){
    $('code').querySelectorAll('.current-code-line').forEach(n=>n.classList.remove('current-code-line'));
    let first:Element|undefined;
    $('code').querySelectorAll<HTMLElement>('[data-address]').forEach(n=>{if(sameAddress(n.dataset.address||'',address)){const line=n.closest('.decomp-line');line?.classList.add('current-code-line');if(line&&!first)first=line;}});
    first?.scrollIntoView({block:'nearest'});
}

$<HTMLSelectElement>('engine-select').onchange=safe(async()=>{
    const select=$<HTMLSelectElement>('engine-select');select.disabled=true;
    try {await api('settings',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({engine:select.value})});notice('Motor guardado para nuevas importaciones. Cada proyecto existente conserva su motor.');}
    finally {select.disabled=false;await refresh();}
});

function applyCapabilities(){
    if(!capabilities)return;
    const caps=capabilities;
    document.querySelectorAll<HTMLButtonElement>('[data-tab]').forEach(button=>{
        const access=tabCapability(button.dataset.tab!,caps);
        button.disabled=!access.enabled;button.title=access.reason;
        if(button.dataset.tab==='code-search')button.textContent=caps.features.cCode.status==='unsupported'?'Buscar IR':'Buscar C';
    });
    if(!tabCapability(tab,caps).enabled)tab='capabilities';
    syncTabs();
}

// Switching presentation keeps both renderers and their selection alive.
const codeWorkspace = $('code-workspace');
const codePanels = codeWorkspace.querySelectorAll<HTMLElement>(':scope > .panel');
document.querySelectorAll<HTMLButtonElement>('[data-code-view]').forEach(button => {
    button.onclick = () => {
        const mode = button.dataset.codeView!;
        if (inlineGraph) closeListingGraph();
        codeWorkspace.dataset.view = mode;
        codePanels[0].hidden = mode === 'pseudo';
        codePanels[1].hidden = mode === 'listing';
        document.querySelectorAll<HTMLButtonElement>('[data-code-view]').forEach(item => {
            item.setAttribute('aria-pressed', String(item === button));
        });
    };
});
