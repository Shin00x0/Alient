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
            colorCodeText(span, token.text, syntax);
            if (token.address) {
                const address = token.address;
                span.dataset.address = address;
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

/** Presentation only: preserve every operand character and never interpret it as HTML. */
export function renderOperands(container: HTMLElement, text: string, branch = false): void {
    const registers = /^(?:[re]?(?:ax|bx|cx|dx|si|di|bp|sp|ip)|[abcd][lh]|r(?:[89]|1[0-5])(?:d|w|b)?|(?:xmm|ymm|zmm|mm|st|k)\d+|[wxvqdsbh]\d+|sp|wsp|lr|fp|pc|[cdefgs]s|[re]?flags)$/i;
    for (const part of text.split(/(\b0x[\da-f]+\b|\b\d+\b|\b[a-z_][\w.]*\b)/gi)) {
        const span = document.createElement('span');
        span.textContent = part;
        span.className = registers.test(part) ? 'asm-register'
            : /^(?:0x[\da-f]+|\d+)$/i.test(part) || (branch && /^(?:loc_|sub_|FUN_|LAB_)/.test(part)) ? 'asm-target' : 'asm-value';
        container.append(span);
    }
}

function colorCodeText(container: HTMLElement, text: string, syntax: number): void {
    // Keep Ghidra's semantic classification and address links on the parent token.
    if (syntax === 1 || syntax === 3) { container.textContent = text; return; }
    const pattern = /(#[ \t]*[a-z]+|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\b(?:return|if|else|while|for|do|switch|case|default|break|continue|goto|sizeof)\b)/g;
    for (const part of text.split(pattern)) {
        const span = document.createElement('span'); span.textContent = part;
        span.className = part.startsWith('#') ? 'code-directive'
            : /^["']/.test(part) ? 'code-string'
            : part === 'return' ? 'code-return'
            : /^(?:if|else|while|for|do|switch|case|default|break|continue|goto|sizeof)$/.test(part) ? 'code-control' : '';
        container.append(span);
    }
}
