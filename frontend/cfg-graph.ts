import {renderOperands} from './code-view.js';
// @ts-expect-error Local browser module served by backend/server.ts.
import * as THREE from '/vendor/three.module.js';
import type { FunctionInfo } from '../backend/types.js';
import { inRange } from './explorer.js';
import { layoutCfg } from './cfg-layout.js';

export function renderCfgGraph(container: HTMLElement, fn: FunctionInfo, navigate: (address: string) => void, selectedAddress: string): () => void {
    const blocks = fn.flowBlocks || [];
    const root = document.createElement('section'); root.className = 'cfg-view';
    const bar = document.createElement('div'); bar.className = 'cfg-toolbar';
    const title = document.createElement('span');
    title.textContent = `${fn.name} · ${blocks.length} bloques · Arrastrar: mover · Rueda: zoom · Doble clic: listing`;
    const fitButton = document.createElement('button'); fitButton.textContent = 'Ver todo';
    const actual = document.createElement('button'); actual.textContent = 'Tamaño real';
    bar.append(title, fitButton, actual);
    const host = document.createElement('div'); host.className = 'cfg-canvas';
    const layer = document.createElement('div'); layer.className = 'cfg-node-layer';
    const legend = document.createElement('div'); legend.className = 'cfg-legend';
    legend.textContent = 'Verde: continuación · Naranja: salto · Azul: flujo · Espacio / Esc: volver al listing';
    root.append(bar, host, legend); container.append(root);
    if (!blocks.length) { host.textContent = 'No hay bloques básicos disponibles.'; return () => root.remove(); }
    let renderer: THREE.WebGLRenderer;
    try { renderer = new THREE.WebGLRenderer({antialias:true}); }
    catch { host.textContent = 'No se pudo iniciar WebGL.'; return () => root.remove(); }
    renderer.setPixelRatio(Math.min(devicePixelRatio, 2)); renderer.setClearColor(0x141c2b);
    host.append(renderer.domElement, layer);
    const scene = new THREE.Scene(), camera = new THREE.OrthographicCamera(-1,1,1,-1,-10,10);
    camera.position.z = 5;
    const ranks = layoutCfg(blocks);
    const cards = blocks.map(block => {
        const rows = fn.instructions.filter(i => inRange(i.address, block.address, block.end));
        const card = document.createElement('div'); card.className = 'cfg-block'; card.dataset.blockAddress = block.address;
        const heading = document.createElement('div'); heading.className = 'cfg-block-title';
        heading.textContent = `loc_${block.address}:`; card.append(heading);
        for (const row of rows) {
            const line = document.createElement('div'); line.className = 'cfg-instruction'; line.dataset.address = row.address;
            const address = document.createElement('span'); address.className = 'cfg-address'; address.textContent = row.address;
            const mnemonic = document.createElement('span'); mnemonic.className = 'cfg-mnemonic';
            const match = row.text.match(/^(\S+)\s*(.*)$/s);
            mnemonic.textContent = match?.[1] || row.text;
            if (/^(?:callq?|bl|blr|blx|jal|jalr)$/i.test(mnemonic.textContent)) mnemonic.classList.add('asm-call');
            const operands = document.createElement('span'); renderOperands(operands, match?.[2] || '', /^(?:j|call|b)/i.test(match?.[1] || ''));
            line.append(address, mnemonic, operands);
            if (row.comment) { const comment = document.createElement('span'); comment.className = 'cfg-comment'; comment.textContent = '; '+row.comment; line.append(comment); }
            line.onclick = () => { layer.querySelectorAll('.cfg-current').forEach(n=>n.classList.remove('cfg-current')); line.classList.add('cfg-current'); };
            line.ondblclick = () => navigate(row.address);
            card.append(line);
        }
        if (!rows.length) { const missing = document.createElement('div'); missing.textContent = 'Instrucciones no exportadas — doble clic para abrir listing'; card.append(missing); }
        card.ondblclick = event => { if (!(event.target as Element).closest('.cfg-instruction')) navigate(block.address); };
        layer.append(card);
        return {block, card, rank:ranks.get(block.address)!.rank, width:card.offsetWidth, height:card.offsetHeight, x:0, y:0};
    });
    let top = 0;
    for (const rank of [...new Set(cards.map(c=>c.rank))].sort((a,b)=>a-b)) {
        const row = cards.filter(c=>c.rank===rank);
        const total = row.reduce((sum,c)=>sum+c.width,0)+(row.length-1)*90;
        let x=-total/2;
        for (const c of row) { c.x=x; c.y=top; x+=c.width+90; }
        top+=Math.max(...row.map(c=>c.height))+100;
    }
    const byAddress=new Map(cards.map(c=>[c.block.address,c]));
    for(const c of cards) for(const [index,edge] of c.block.edges.entries()) {
        const target=byAddress.get(edge.to); if(!target)continue;
        const sx=c.x+c.width/2+index*12, sy=c.y+c.height, tx=target.x+target.width/2, ty=target.y;
        let points: number[][];
        if(ty>sy) { const middle=(sy+ty)/2; points=[[sx,sy],[sx,middle],[tx,middle],[tx,ty-4]]; }
        else { const side=Math.max(c.x+c.width,target.x+target.width)+40+index*20; points=[[sx,sy],[sx,sy+25],[side,sy+25],[side,ty-25],[tx,ty-25],[tx,ty-4]]; }
        const color=/FALL/i.test(edge.type)?0x69d2b0:/JUMP|BRANCH/i.test(edge.type)?0xf1be65:0x8fb9ff;
        const material=new THREE.LineBasicMaterial({color});
        scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(points.map(([x,y])=>new THREE.Vector3(x,-y,0))),material));
        scene.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([[tx-5,ty-12],[tx,ty-4],[tx+5,ty-12]].map(([x,y])=>new THREE.Vector3(x,-y,0))),material));
    }
    const selected=cards.find(c=>inRange(selectedAddress,c.block.address,c.block.end))||cards[0];
    selected.card.classList.add('cfg-selected');
    let zoom=1, cx=selected.x+selected.width/2, cy=selected.y+Math.min(selected.height/2,180);
    let width=1,height=1;
    function render() {
        camera.left=-width/2;camera.right=width/2;camera.top=height/2;camera.bottom=-height/2;
        camera.position.set(cx,-cy,5); camera.zoom=zoom;camera.updateProjectionMatrix();renderer.render(scene,camera);
        for(const c of cards) c.card.style.transform=`translate(${width/2+(c.x-cx)*zoom}px,${height/2+(c.y-cy)*zoom}px) scale(${zoom})`;
    }
    const resize=()=>{width=Math.max(host.clientWidth,1);height=Math.max(host.clientHeight,1);renderer.setSize(width,height,false);render();};
    const observer=new ResizeObserver(resize);observer.observe(host);resize();
    fitButton.onclick=()=>{const left=Math.min(...cards.map(c=>c.x))-60,right=Math.max(...cards.map(c=>c.x+c.width))+60;cx=(left+right)/2;cy=(top-100)/2;zoom=Math.min(width/(right-left),height/(top+20),1);render();};
    actual.onclick=()=>{zoom=1;cx=selected.x+selected.width/2;cy=selected.y+Math.min(selected.height/2,180);render();};
    host.onwheel=e=>{e.preventDefault();const r=host.getBoundingClientRect(),x=e.clientX-r.left-width/2,y=e.clientY-r.top-height/2;const next=Math.max(.02,Math.min(3,zoom*Math.exp(-e.deltaY*.001)));cx+=x/zoom-x/next;cy+=y/zoom-y/next;zoom=next;render();};
    let drag:{x:number;y:number;cx:number;cy:number}|undefined;
    host.onpointerdown=e=>{if(e.button!==0)return;drag={x:e.clientX,y:e.clientY,cx,cy};};
    host.onpointermove=e=>{if(!drag)return;if(Math.hypot(e.clientX-drag.x,e.clientY-drag.y)>4)host.setPointerCapture(e.pointerId);cx=drag.cx-(e.clientX-drag.x)/zoom;cy=drag.cy-(e.clientY-drag.y)/zoom;render();};
    host.onpointerup=host.onpointercancel=()=>{drag=undefined;};
    fitButton.click();
    return ()=>{observer.disconnect();scene.traverse((o: import('three').Object3D)=>{const line=o as import('three').Line;line.geometry?.dispose();const m=line.material;if(Array.isArray(m))m.forEach(x=>x.dispose());else m?.dispose();});renderer.dispose();root.remove();};
}
