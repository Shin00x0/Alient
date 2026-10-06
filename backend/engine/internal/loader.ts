/** Standalone binary readers. No Ghidra code or runtime dependency. */
export interface Region {name:string;address:bigint;size:number;offset:number;fileSize:number;permissions:string;code:boolean}
export interface BinarySymbol {name:string;address:bigint;function:boolean;external:boolean}
export interface Image {imageBase:bigint;format:string;architecture:string;entry?:bigint;regions:Region[];symbols:BinarySymbol[]}
export const hex=(value:bigint)=>value.toString(16).padStart(8,'0');
export function loadImage(bytes:Buffer):Image {
    function range(offset:number,size:number){if(!Number.isSafeInteger(offset)||!Number.isSafeInteger(size)||offset<0||size<0||offset+size>bytes.length)throw Error('Binario truncado o rango de archivo inválido.');}
    const u16=(p:number)=>{range(p,2);return bytes.readUInt16LE(p);};
    const u32=(p:number)=>{range(p,4);return bytes.readUInt32LE(p);};
    const u64=(p:number)=>{range(p,8);return bytes.readBigUInt64LE(p);};
    const number=(v:bigint)=>{if(v>BigInt(Number.MAX_SAFE_INTEGER))throw Error('Tamaño de archivo fuera de rango.');return Number(v);};
    const str=(p:number,n:number)=>{range(p,n);const end=bytes.indexOf(0,p);return bytes.toString('utf8',p,end>=p&&end<p+n?end:p+n);};
    const regions:Region[]=[],symbols:BinarySymbol[]=[];
    let imageBase:bigint|undefined;
    range(0,4);
    if(u32(0)===0xfeedfacf){
        range(0,32);
        if(u32(4)!==0x100000c)throw Error('Motor interno: Mach-O compatible únicamente con ARM64. Usa Ghidra para esta arquitectura.');
        if(![2,6,8].includes(u32(12)))throw Error('Motor interno: se requiere un Mach-O enlazado, no un objeto relocatable.');
        const count=u32(16),size=u32(20);range(32,size);if(count>size/8)throw Error('Tabla de comandos Mach-O inválida.');
        let p=32,entryOffset:number|undefined,symtab:{offset:number;count:number;strings:number;size:number}|undefined;
        for(let i=0;i<count;i++){
            const cmd=u32(p),length=u32(p+4);if(length<8||p+length>32+size)throw Error('Comando Mach-O inválido.');
            if(cmd===0x19){
                if(length<72)throw Error('Segmento Mach-O truncado.');
                const n=u32(p+64),prot=u32(p+60);
                if(u64(p+48)>0n&&prot){const base=u64(p+24);if(imageBase===undefined||base<imageBase)imageBase=base;}
                if(72+n*80>length)throw Error('Secciones Mach-O truncadas.');
                for(let j=0;j<n;j++){
                    const q=p+72+j*80,name=str(q,16),address=u64(q+32),length=number(u64(q+40)),offset=u32(q+48),flags=u32(q+64);
                    const zero=[1,12,18].includes(flags&255),fileSize=zero?0:length;range(offset,fileSize);
                    regions.push({name,address,size:length,offset,fileSize,permissions:(prot&1?'r':'-')+(prot&2?'w':'-')+(prot&4?'x':'-'),code:!!(flags&0x80000400)});
                }
            } else if(cmd===2){if(length<24)throw Error('Símbolos Mach-O truncados.');symtab={offset:u32(p+8),count:u32(p+12),strings:u32(p+16),size:u32(p+20)};}
            else if(cmd===0x80000028){if(length<24)throw Error('Entrada Mach-O truncada.');entryOffset=number(u64(p+8));}
            p+=length;
        }
        if(symtab){range(symtab.offset,symtab.count*16);range(symtab.strings,symtab.size);
            for(let i=0;i<symtab.count;i++){const p=symtab.offset+i*16,idx=u32(p),type=bytes[p+4],section=bytes[p+5],address=u64(p+8);if(idx>=symtab.size||type&0xe0)continue;const name=str(symtab.strings+idx,symtab.size-idx);if(!name)continue;const external=(type&14)===0;symbols.push({name,address,external,function:!external&&(type&14)===14&&!!regions[section-1]?.code});}
        }
        const entryRegion=entryOffset===undefined?undefined:regions.find(r=>entryOffset!>=r.offset&&entryOffset!<r.offset+r.fileSize);
        return {imageBase:imageBase??0n,format:'Mach-O 64-bit',architecture:'AARCH64:LE:64',regions,symbols,entry:entryRegion?entryRegion.address+BigInt(entryOffset!-entryRegion.offset):undefined};
    }
    if(bytes.subarray(0,4).equals(Buffer.from([127,69,76,70]))){
        range(0,64);if(bytes[4]!==2||bytes[5]!==1||u16(18)!==183)throw Error('Motor interno: ELF compatible únicamente con ARM64 de 64 bits little-endian. Usa Ghidra para esta arquitectura.');
        if(![2,3].includes(u16(16)))throw Error('Motor interno: ELF debe ser ejecutable o biblioteca enlazada.');
        const ph=number(u64(32)),phSize=u16(54),phCount=u16(56),sh=number(u64(40)),shSize=u16(58),shCount=u16(60),names=u16(62);
        if(phCount&&phSize<56||shCount&&shSize<64)throw Error('Cabeceras ELF inválidas.');range(ph,phCount*phSize);range(sh,shCount*shSize);
        for(let i=0;i<phCount;i++){const p=ph+i*phSize;if(u32(p)===1){const base=u64(p+16);if(imageBase===undefined||base<imageBase)imageBase=base;}}
        const sections=Array.from({length:shCount},(_,i)=>{const p=sh+i*shSize;return {name:u32(p),type:u32(p+4),flags:u64(p+8),address:u64(p+16),offset:number(u64(p+24)),size:number(u64(p+32)),link:u32(p+40),entrySize:number(u64(p+56))};});
        const namesSection=sections[names];
        for(const section of sections){if(!(section.flags&2n))continue;const fileSize=section.type===8?0:section.size;range(section.offset,fileSize);let name='section';if(namesSection&&section.name<namesSection.size)name=str(namesSection.offset+section.name,namesSection.size-section.name);regions.push({name,address:section.address,size:section.size,offset:section.offset,fileSize,permissions:'r'+(section.flags&1n?'w':'-')+(section.flags&4n?'x':'-'),code:!!(section.flags&4n)});}
        // Stripped ELF without section headers: load file-backed segments instead.
        if(!regions.length)for(let i=0;i<phCount;i++){const p=ph+i*phSize;if(u32(p)!==1)continue;const flags=u32(p+4),offset=number(u64(p+8)),fileSize=number(u64(p+32)),size=number(u64(p+40));if(fileSize>size)throw Error('Segmento ELF inválido.');range(offset,fileSize);regions.push({name:'LOAD_'+i,address:u64(p+16),size,offset,fileSize,permissions:(flags&4?'r':'-')+(flags&2?'w':'-')+(flags&1?'x':'-'),code:!!(flags&1)});}
        for(const section of sections){if(![2,11].includes(section.type))continue;const strings=sections[section.link];if(!strings||section.entrySize<24||section.size%section.entrySize)throw Error('Tabla de símbolos ELF inválida.');range(section.offset,section.size);range(strings.offset,strings.size);for(let i=0;i<section.size;i+=section.entrySize){const p=section.offset+i,idx=u32(p);if(idx>=strings.size)continue;const name=str(strings.offset+idx,strings.size-idx);if(name)symbols.push({name,address:u64(p+8),external:u16(p+6)===0,function:(bytes[p+4]&15)===2&&u16(p+6)!==0});}}
        return {imageBase:imageBase??0n,format:'ELF 64-bit',architecture:'AARCH64:LE:64',entry:u64(24),regions,symbols};
    }
    throw Error('Motor interno: formato no soportado. Admite Mach-O ARM64 y ELF ARM64 enlazados de 64 bits; selecciona Ghidra para otros formatos.');
}
