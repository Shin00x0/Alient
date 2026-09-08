import type {FunctionInfo} from '../backend/types.js';

/** Exact text reconstruction; no regex lexer, renaming, or code rewriting. */
export function markupText(lines: NonNullable<FunctionInfo['codeLines']>): string {
    return lines.map(line => line.indent + line.tokens.map(token => token.text).join('') + '\n').join('');
}

export function renderCode(container: HTMLElement, fn: FunctionInfo, navigate: (address: string) => void): void {
    container.replaceChildren();
    if (fn.decompileStatus === 'external' || fn.decompileStatus === 'no-instructions') {
        container.textContent = fn.decompileStatus === 'external'
            ? `Función importada: ${fn.name}\n\n${fn.signature}\n\nSu implementación no está incluida en este ejecutable.\nNo hay instrucciones disponibles para decompilar.`
            : 'No hay instrucciones analizadas para esta función. No se generó pseudocódigo.';
        return;
    }
    // Older exports remain readable. Inconsistent markup must never change the displayed code.
    if (!fn.codeLines?.length || markupText(fn.codeLines) !== fn.code) {
        container.textContent = fn.code || fn.error || 'Sin pseudocódigo disponible.';
        return;
    }
    const fragment = document.createDocumentFragment();
    fn.codeLines.forEach((line, index) => {
        const row = document.createElement('span');
        row.className = 'decomp-line';
        row.dataset.line = String(index + 1);
        row.append(document.createTextNode(line.indent));
        for (const token of line.tokens) {
            const span = document.createElement('span');
            const syntax = Number.isInteger(token.syntax) && token.syntax >= 0 && token.syntax <= 10 ? token.syntax : 8;
            span.className = `syntax-${syntax}`;
            span.textContent = token.text;
            if (token.address) {
                const address = token.address;
                span.classList.add('code-location');
                span.title = `Ver instrucción ${address}`;
                span.tabIndex = 0;
                span.setAttribute('role', 'link');
                span.onclick = () => navigate(address);
                span.onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); navigate(address); } };
            }
            row.append(span);
        }
        fragment.append(row, document.createTextNode('\n'));
    });
    container.append(fragment);
}
