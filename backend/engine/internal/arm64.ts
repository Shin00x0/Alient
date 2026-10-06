/** Small ARM64 decoder + register-level IR. Unknown words are never guessed. */
export interface Operation {text:string;ir:string;known:boolean;target?:bigint;reference?:bigint;flow?:'call'|'jump'|'conditional'|'return'|'indirect';writes?:number;invalidates?:number[];constant?:bigint;addBase?:number;addImmediate?:bigint}
const signed=(value:number,bits:number)=>BigInt(value>=2**(bits-1)?value-2**bits:value);
const address=(v:bigint)=>'0x'+BigInt.asUintN(64,v).toString(16);
export function decodeArm64(w:number,pc:bigint):Operation {
    const match=(mask:number,value:number)=>((w&mask)>>>0)===(value>>>0);
    const sf=w>>>31,rd=w&31,rn=(w>>>5)&31,rm=(w>>>16)&31;
    const reg=(n:number,sp=false)=>n===31?(sp?(sf?'sp':'wsp'):'0'):(sf?'x':'w')+n;
    const result=(text:string,ir:string,extra:Partial<Operation>={}):Operation=>({text,ir,known:true,...extra});
    if(w===0xd503201f)return result('nop','/* nop */');
    if(match(0xfffffc1f,0xd65f0000))return result(`ret x${rn}`,`return_to(x${rn});`,{flow:'return'});
    if(match(0xfffffc1f,0xd61f0000)||match(0xfffffc1f,0xd63f0000)){const call=!!(w&0x200000);return result(`${call?'blr':'br'} x${rn}`,`${call?'call_indirect':'jump_indirect'}(x${rn});`,{flow:call?'call':'indirect'});}
    if(match(0x7c000000,0x14000000)){const target=BigInt.asUintN(64,pc+(signed(w&0x3ffffff,26)<<2n)),call=!!(w>>>31);return result(`${call?'bl':'b'} ${address(target)}`,`${call?'call':'goto'} ${address(target)};`,{target,flow:call?'call':'jump'});}
    if(match(0xff000010,0x54000000)){const target=BigInt.asUintN(64,pc+(signed((w>>>5)&0x7ffff,19)<<2n));const cond=['eq','ne','cs','cc','mi','pl','vs','vc','hi','ls','ge','lt','gt','le','al','nv'][w&15];return result(`b.${cond} ${address(target)}`,`if (condition_${cond}(NZCV)) goto ${address(target)};`,{target,flow:'conditional'});}
    if(match(0x7e000000,0x34000000)){const target=BigInt.asUintN(64,pc+(signed((w>>>5)&0x7ffff,19)<<2n)),nz=!!(w&0x1000000);return result(`${nz?'cbnz':'cbz'} ${reg(rd)}, ${address(target)}`,`if (${reg(rd)} ${nz?'!=':'=='} 0) goto ${address(target)};`,{target,flow:'conditional'});}
    if(match(0x1f000000,0x10000000)){const page=!!sf,imm=signed(((w>>>5)&0x7ffff)*4+((w>>>29)&3),21),target=BigInt.asUintN(64,page?(pc&~4095n)+(imm<<12n):pc+imm);return result(`${page?'adrp':'adr'} x${rd}, ${address(target)}`,`${rd===31?'discard':'x'+rd} = ${address(target)};`,{writes:rd,constant:target,reference:target});}
    if(match(0x1f800000,0x12800000)){const opc=(w>>>29)&3,shift=((w>>>21)&3)*16;if(opc===1||!sf&&shift>=32)return unknown(w);const immediate=BigInt((w>>>5)&65535)<<BigInt(shift),bits=sf?64:32,constant=opc===0?BigInt.asUintN(bits,~immediate):immediate,name=opc===0?'movn':opc===2?'movz':'movk';return result(`${name} ${reg(rd)}, #${(w>>>5)&65535}, lsl #${shift}`,`${reg(rd)} = ${opc===3?`(${reg(rd)} & ~${address(65535n<<BigInt(shift))}) | ${address(immediate)}`:address(constant)};`,{writes:rd,...(opc!==3?{constant}:{})});}
    if(match(0x1f800000,0x11000000)){const sub=!!(w&0x40000000),flags=!!(w&0x20000000),imm=BigInt((w>>>10)&4095)<<BigInt(w&0x400000?12:0),operation=sub?'-':'+';return result(`${sub?'sub':'add'}${flags?'s':''} ${reg(rd,!flags)}, ${reg(rn,true)}, #${imm}`,`${flags?'NZCV, ':''}${rd===31&&flags?'discard':reg(rd,true)} = ${flags?'flags_and_':''}${sf?'u64':'u32'}(${reg(rn,true)} ${operation} ${imm});`,{writes:rd,...(!sub&&!flags&&sf?{addBase:rn,addImmediate:imm}:{})});}
    if(match(0x1f200000,0x0b000000)){const shift=(w>>>22)&3,amount=(w>>>10)&63;if(shift===3||!sf&&amount>=32)return unknown(w);const sub=!!(w&0x40000000),flags=!!(w&0x20000000),rhs=amount?`${['lsl','lsr','asr'][shift]}(${reg(rm)}, ${amount})`:reg(rm);return result(`${sub?'sub':'add'}${flags?'s':''} ${reg(rd)}, ${reg(rn)}, ${reg(rm)}, ${['lsl','lsr','asr'][shift]} #${amount}`,`${flags?'NZCV, ':''}${rd===31?'discard':reg(rd)} = ${flags?'flags_and_':''}${sf?'u64':'u32'}(${reg(rn)} ${sub?'-':'+'} ${rhs});`,{writes:rd});}
    if(match(0x1f200000,0x0a000000)){const opc=(w>>>29)&3,shift=(w>>>22)&3,amount=(w>>>10)&63;if(!sf&&amount>=32)return unknown(w);const invert=!!(w&0x200000),rhs=`${invert?'~':''}${['lsl','lsr','asr','ror'][shift]}(${reg(rm)}, ${amount})`,op=['&','|','^','&'][opc];return result(`${['and','orr','eor','ands'][opc]}${invert?' (inverted operand)':''} ${reg(rd)}, ${reg(rn)}, ${reg(rm)}, ${['lsl','lsr','asr','ror'][shift]} #${amount}`,`${opc===3?'NZCV, ':''}${rd===31?'discard':reg(rd)} = ${opc===3?'logical_flags_and_':''}${sf?'u64':'u32'}(${reg(rn)} ${op} ${rhs});`,{writes:rd});}
    // Integer pair loads/stores with offset, pre-index and post-index addressing.
    if(match(0x3e000000,0x28000000)){
        const opc=w>>>30,mode=(w>>>23)&3,load=!!(w&0x400000),rt2=(w>>>10)&31;
        if(![0,2].includes(opc)||mode===0)return unknown(w);
        const size=opc===2?8:4,offset=Number(signed((w>>>15)&127,7))*size,base=rn===31?'sp':'x'+rn;
        if(mode!==2&&rn!==31&&(rn===rd||rn===rt2)||load&&rd===rt2)return unknown(w);
        const r=(n:number)=>n===31?'0':(size===8?'x':'w')+n;
        const location=mode===1?base:`(${base} + ${offset})`;
        const access=load?`${rd===31?'discard':r(rd)}, ${rt2===31?'discard':r(rt2)} = load_pair_u${size*8}(${location});`:`store_pair_u${size*8}(${location}, ${r(rd)}, ${r(rt2)});`;
        return result(`${load?'ldp':'stp'} ${r(rd)}, ${r(rt2)}, [${base}${mode===1?'':', #'+offset}]${mode===3?'!':mode===1?', #'+offset:''}`,access+(mode===2?'':` ${base} = u64(${base} + ${offset});`),{invalidates:[...(load?[rd,rt2]:[]),...(mode!==2?[rn]:[])]});
    }
    // Integer unscaled loads/stores and write-back variants.
    if(match(0x3f200000,0x38000000)){
        const size=1<<(w>>>30),opc=(w>>>22)&3,mode=(w>>>10)&3;
        if(opc>1||mode===2)return unknown(w);
        const load=opc===1,offset=Number(signed((w>>>12)&511,9)),base=rn===31?'sp':'x'+rn,r=rd===31?'0':(size===8?'x':'w')+rd;
        if(mode!==0&&rn!==31&&rn===rd)return unknown(w);
        const location=mode===1?base:`(${base} + ${offset})`;
        return result(`${mode===0?(load?'ldur':'stur'):(load?'ldr':'str')}${size===1?'b':size===2?'h':''} ${r}, [${base}${mode===1?'':', #'+offset}]${mode===3?'!':mode===1?', #'+offset:''}`,(load?`${rd===31?'discard':r} = load_u${size*8}(${location});`:`store_u${size*8}(${location}, ${r});`)+(mode===0?'':` ${base} = u64(${base} + ${offset});`),{invalidates:[...(load?[rd]:[]),...(mode!==0?[rn]:[])]});
    }
    if(match(0x7fe00000,0x1b000000)){
        const ra=(w>>>10)&31,subtract=!!(w&0x8000);
        return result(`${subtract?'msub':'madd'} ${reg(rd)}, ${reg(rn)}, ${reg(rm)}, ${reg(ra)}`,`${rd===31?'discard':reg(rd)} = ${sf?'u64':'u32'}(${reg(ra)} ${subtract?'-':'+'} ${reg(rn)} * ${reg(rm)});`,{writes:rd});
    }
    // Unsigned immediate integer loads/stores (not SIMD or sign-extending variants).
    if(match(0x3f000000,0x39000000)){const size=1<<(w>>>30),opc=(w>>>22)&3;if(opc>1)return unknown(w);const load=opc===1,offset=((w>>>10)&4095)*size,r=rd===31?'0':(size===8?'x':'w')+rd,base=rn===31?'sp':'x'+rn;return result(`${load?'ldr':'str'}${size===1?'b':size===2?'h':''} ${r}, [${base}, #${offset}]`,load?`${rd===31?'discard':r} = load_u${size*8}(${base} + ${offset});`:`store_u${size*8}(${base} + ${offset}, ${r});`,load?{writes:rd}:{});}
    return unknown(w);
}
function unknown(w:number):Operation{return {text:'.inst 0x'+w.toString(16).padStart(8,'0'),ir:'/* Instrucción no soportada: 0x'+w.toString(16).padStart(8,'0')+'; efectos desconocidos */',known:false};}
