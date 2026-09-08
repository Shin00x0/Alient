import { renderCode } from './code-view.js';
import type { Analysis, FunctionInfo, Project } from '../backend/types.js';
const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
let project: Project | undefined, analysis: Analysis | undefined, selected: FunctionInfo | undefined, tab = 'strings', hexOffset = 0, openVersion = 0;
const statusNames: Record<string, string> = { queued: 'En cola', analyzing: 'Analizando…', ready: 'Completado', failed: 'Error', cancelled: 'Cancelado' };
function notice(message: string, error = false) { $('notice').textContent = message; $('notice').classList.toggle('error', error); }
async function api<T>(path: string, options?: RequestInit): Promise<T> { const response = await fetch('/api/' + path, options); const data = await response.json(); if (!response.ok)
    throw Error(data.error || 'Error de servidor'); return data; }
function el(tag: string, text?: string, className?: string) { const node = document.createElement(tag); if (text !== undefined)
    node.textContent = text; if (className)
    node.className = className; return node; }
function safe(action: () => Promise<void>) { return () => { void action().catch(e => notice(e.message, true)); }; }
async function refresh() { const health = await api<{
    engine: string;
    message: string;
}>('health'); $('engine').textContent = health.engine === 'ready' ? '● Motor conectado' : '○ Motor no configurado'; $('engine').title = health.message; const all = await api<Project[]>('projects'); $('project-count').textContent = String(all.length); $('projects').replaceChildren(); if (!all.length)
    $('projects').append(el('div', 'Todavía no hay proyectos.', 'help')); for (const p of all) {
    const b = el('button', p.name, p.id === project?.id ? 'selected' : '');
    b.append(el('small', statusNames[p.status]));
    b.onclick = safe(() => openProject(p.id));
    $('projects').append(b);
} }
async function openProject(id: string) { const version = ++openVersion; const p = await api<Project>('projects/' + id); if (version !== openVersion)
    return; project = p; analysis = undefined; selected = undefined; hexOffset = 0; $('filename').textContent = p.name; $('architecture').textContent = '—'; $('overview').replaceChildren(); $('listing').replaceChildren(el('div', 'Esperando resultados del análisis.', 'empty')); $('code').textContent = 'El pseudocódigo aparecerá al completar el análisis.'; $('signature').textContent = 'Selecciona una función'; $('decompile-status').textContent = 'Motor Ghidra'; $('export').toggleAttribute('disabled', true); $('copy-code').toggleAttribute('disabled', true); $('reanalyze').toggleAttribute('disabled', ['queued','analyzing'].includes(p.status)); renderFunctions(); await renderDetails(); if (p.status === 'ready') {
    const result = await api<Analysis>('projects/' + id + '/result');
    if (version !== openVersion)
        return;
    analysis = result;
    $('architecture').textContent = result.language;
    for (const [label, value] of [['Formato', result.format], ['Base', '0x' + result.imageBase], ['Funciones', `${result.functions.length} / ${result.listingFunctions ?? result.totalFunctions} · ${result.externalSymbols ?? 0} símbolos externos`]]) {
        const span = el('span', label);
        span.append(el('b', value));
        $('overview').append(span);
    }
    $('export').removeAttribute('disabled');
    renderFunctions();
    if (result.functions.length)
        selectFunction(result.functions[0]);
    else {
        $('listing').replaceChildren(el('div', 'No se encontraron funciones. Consulta memoria, cadenas o hexadecimal.', 'empty'));
        $('code').textContent = 'No hay funciones decompilables.';
        await renderDetails();
    }
    notice(result.limits);
}
else {
    notice(p.error || statusNames[p.status], p.status === 'failed');
} $('status').textContent = `${statusNames[p.status]} · ${(p.size / 1024).toFixed(1)} KiB`; await refresh(); }
function renderFunctions() { const q = $<HTMLInputElement>('search').value.toLowerCase(); $('functions').replaceChildren(); const functions = analysis?.functions.filter(f => `${f.name} ${f.address} ${project?.annotations[f.address]?.label || ''}`.toLowerCase().includes(q)) || []; $('function-count').textContent = String(functions.length); for (const f of functions) {
    const b = el('button', project?.annotations[f.address]?.label || f.name, f === selected ? 'selected' : '');
    b.append(el('small', f.address + (f.kind === 'external' ? ' · Importada' : f.kind === 'thunk' ? ' · Thunk' : '')));
    b.onclick = () => selectFunction(f);
    $('functions').append(b);
} }
function selectFunction(f: FunctionInfo) { selected = f; $('signature').textContent = f.decompiledSignature || f.signature; $('listing').replaceChildren(); for (const row of f.instructions) {
    const line = el('div', undefined, 'ins');
    line.dataset.address = row.address;
    line.append(el('span', row.address, 'address'), el('span', row.bytes, 'bytes'), el('span', row.text));
    $('listing').append(line);
} if (f.instructionsTruncated)
    $('listing').append(el('div', 'Vista limitada a 500 instrucciones.', 'help')); renderCode($('code'), f, (address) => { const row = Array.from($('listing').children).find(n => (n as HTMLElement).dataset.address === address) as HTMLElement | undefined; if (row) { $('listing').querySelectorAll('.current-instruction').forEach(n => n.classList.remove('current-instruction')); row.classList.add('current-instruction'); row.scrollIntoView({block:'nearest'}); } else notice('La instrucción no está incluida en esta vista limitada.'); }); $('copy-code').toggleAttribute('disabled', !f.code); $('code').classList.remove('empty'); $('decompile-status').textContent = f.decompileStatus === 'external' ? 'Importación · implementación no incluida' : f.decompileStatus === 'no-instructions' ? 'Sin instrucciones' : f.error ? 'Decompilación incompleta' : f.warning ? 'Ghidra: ' + f.warning : `${f.name} · Ghidra ${analysis?.engineVersion || 'exportación anterior'} · ${f.address}`; renderFunctions(); void renderDetails().catch(e => notice(e.message, true)); }
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
    const container = $('details');
    container.replaceChildren();
    if (!project) {
        container.append(el('div', 'Abre un proyecto para explorar sus resultados.', 'help'));
        return;
    }
    const p = project;
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
function syncTabs() { document.querySelectorAll<HTMLButtonElement>('[data-tab]').forEach(b => b.setAttribute('aria-selected', String(b.dataset.tab === tab))); }
document.querySelectorAll<HTMLButtonElement>('[data-tab]').forEach(b => b.onclick = safe(async () => { tab = b.dataset.tab!; syncTabs(); await renderDetails(); }));
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
$('copy-code').onclick = safe(async () => { if (!selected?.code) return; await navigator.clipboard.writeText(selected.code); notice('Pseudocódigo original de Ghidra copiado.'); });
