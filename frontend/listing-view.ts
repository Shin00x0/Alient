import {renderOperands} from './code-view.js';
import type {ListingInstruction,ListingPage} from '../backend/types.js';
export class ListingView {
    private project=''; private sequence=0; private data?:ListingPage; private busy=false;
    private focused='';
    constructor(private container:HTMLElement,private controls:HTMLElement,private select:(row:ListingInstruction)=>void,private navigate:(address:string)=>void,private error:(message:string)=>void,private showFlow:(row:ListingInstruction)=>void) {
        container.tabIndex=0;
        container.addEventListener('keydown',e=>{
            if(e.target instanceof HTMLButtonElement)return;
            if(e.key===' '||e.code==='Space'){const row=(this.data?.rows||[]).find(item=>item.address===this.focused);if(row){e.preventDefault();if(!e.repeat&&!e.ctrlKey&&!e.metaKey&&!e.altKey)this.showFlow(row);}return;}
            if(e.key==='PageDown'||e.key==='PageUp'){e.preventDefault();void this.page((this.data?.page||0)+(e.key==='PageDown'?1:-1));}
            if(e.key==='ArrowDown'||e.key==='ArrowUp'){
                e.preventDefault();const rows=this.data?.rows||[],index=rows.findIndex(r=>r.address===this.focused),next=index+(e.key==='ArrowDown'?1:-1);
                if(rows[next])this.pick(rows[next]);else if(e.key==='ArrowDown')void this.page((this.data?.page||0)+1);else void this.page((this.data?.page||0)-1,true);
            }
        });
    }
    reset(project:string){this.project=project;this.sequence++;this.data=undefined;this.focused='';this.busy=false;this.controls.replaceChildren();}
    async address(address:string){await this.load(new URLSearchParams({address}));}
    async page(page:number,last=false){if(this.busy||page<0||this.data&&page>=this.data.totalPages)return;await this.load(new URLSearchParams({page:String(page)}),last);}
    private pick(row:ListingInstruction){this.focused=row.address;for(const node of this.container.querySelectorAll<HTMLElement>('[data-listing-address]')){const active=node.dataset.listingAddress===row.address;node.classList.toggle('current-instruction',active);node.setAttribute('aria-selected',String(active));if(active)node.scrollIntoView({block:'nearest'});}this.select(row);}
    private async load(params:URLSearchParams,last=false){
        if(!this.project)return;
        const request=++this.sequence;this.busy=true;this.toolbar();
        this.container.setAttribute('aria-busy','true');
        try {
            const response=await fetch(`/api/projects/${this.project}/listing?${params}`),result=await response.json();
            if(request!==this.sequence)return;
            if(!response.ok)throw Error(result.error||'No se pudo cargar el listing.');
            this.data=result;this.render();
            const row=last?this.data!.rows.at(-1):this.data!.rows.find(r=>r.address===this.data!.selected)||this.data!.rows[0];
            if(row)this.pick(row);
            if(this.data!.requested&&!this.data!.exact)this.error(`No hay una instrucción en ${this.data!.requested}. Se muestra la más cercana del espacio de memoria.`);
        }catch(e){if(request!==this.sequence)return;this.container.replaceChildren();const message=document.createElement('div');message.className='empty';message.textContent=(e as Error).message;this.container.append(message);this.error(message.textContent);}
        finally{if(request===this.sequence){this.busy=false;this.container.setAttribute('aria-busy','false');this.toolbar();}}
    }
    private toolbar(){
        this.controls.replaceChildren();const page=this.data?.page||0,total=this.data?.totalPages||0;
        for(const [label,target]of [['⏮',0],['Anterior',page-1],['Siguiente',page+1],['⏭',total-1]] as const){const b=document.createElement('button');b.textContent=label;b.title=label==='⏮'?'Primera página':label==='⏭'?'Última página':label;b.disabled=this.busy||!total||target<0||target>=total||target===page;b.onclick=()=>void this.page(target);this.controls.append(b);}
        const form=document.createElement('form'),input=document.createElement('input');input.type='number';input.min='1';input.max=String(total||1);input.value=String(total?page+1:0);input.setAttribute('aria-label','Página del listing');input.disabled=this.busy||!total;
        const text=document.createElement('span');text.textContent=` / ${total} · ${this.data?.totalInstructions.toLocaleString()||0} instrucciones${this.busy?' · Cargando…':''}`;
        form.append(input,text);form.onsubmit=e=>{e.preventDefault();void this.page(Number(input.value)-1);};this.controls.append(form);
    }
    private render(){
        this.container.replaceChildren();let priorFunction:string|undefined;
        if(!this.data?.rows.length){const empty=document.createElement('p');empty.textContent='Ghidra no ha definido instrucciones en este programa.';this.container.append(empty);return;}
        for(const row of this.data.rows){
            if(row.functionAddress!==priorFunction){const header=document.createElement('div');header.className='listing-function';header.textContent=row.function?`${row.function} · ${row.functionAddress}`:'Código fuera de funciones';this.container.append(header);priorFunction=row.functionAddress;}
            const line=document.createElement('div');line.className='listing-row';line.dataset.listingAddress=row.address;line.dataset.address=row.address;line.dataset.functionAddress=row.functionAddress||'';line.dataset.comment=row.comment||'';line.setAttribute('role','option');line.setAttribute('aria-selected','false');
            for(const [value,cls]of [[row.space+':'+row.address,'address'],[row.bytes,'bytes']]as const){const span=document.createElement('span');span.className=cls;span.textContent=value;line.append(span);}
            const assembly=document.createElement('span');assembly.className='assembly';
            const parts=row.text.match(/^(\S+)\s*(.*)$/s);
            const mnemonic=document.createElement('span');mnemonic.className='mnemonic';mnemonic.textContent=parts?.[1]||row.text;
            if(/^(j|b\.|cb|tb|ret|call|bl$)/i.test(mnemonic.textContent))mnemonic.classList.add('control-flow');
            if(/^(?:callq?|bl|blr|blx|jal|jalr)$/i.test(mnemonic.textContent))mnemonic.classList.add('asm-call');
            const operands=document.createElement('span');operands.className='operands';renderOperands(operands,parts?.[2]||'',mnemonic.classList.contains('control-flow'));
            assembly.append(mnemonic,operands);line.append(assembly);
            const comment=document.createElement('span');comment.className='listing-comment';comment.textContent=(row.comment||row.label)?'; '+(row.comment||row.label):'';line.append(comment);
            const refs=document.createElement('span');refs.className='listing-links';for(const ref of row.references){const link=document.createElement('button');link.textContent=ref.to;link.title=ref.type;link.onclick=e=>{e.stopPropagation();this.navigate(ref.to);};refs.append(link);}line.append(refs);
            line.onclick=()=>{this.container.focus({preventScroll:true});this.pick(row);};this.container.append(line);
        }
    }
}
