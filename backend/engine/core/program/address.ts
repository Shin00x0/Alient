import type {Address,AddressRange} from './types.ts';
export function address(space:string,offset:bigint|string):Address {
    if(!/^[A-Za-z_][\w.-]*$/.test(space))throw Error('Nombre de espacio inválido.');
    if(typeof offset==='string'&&!/^(?:0x)?[\da-f]+$/i.test(offset))throw Error('Dirección hexadecimal inválida.');
    const value=typeof offset==='bigint'?offset:BigInt('0x'+offset.replace(/^0x/i,''));
    if(value<0n||value>0xffffffffffffffffn)throw Error('Dirección fuera del rango de 64 bits.');
    return {space,offset:value.toString(16)};
}
export function offset(a:Address):bigint {return BigInt('0x'+a.offset);}
export function range(start:Address,size:bigint|number|string):AddressRange {
    if(typeof size==='number'&&!Number.isSafeInteger(size))throw Error('Tamaño numérico impreciso. Usa bigint.');
    if(typeof size==='string'&&!/^[1-9]\d*$/.test(size))throw Error('Tamaño decimal inválido.');
    const length=BigInt(size);
    if(length<=0n)throw Error('El rango debe tener tamaño positivo.');
    const result={start:address(start.space,start.offset),size:length.toString()};
    if(end(result)>1n<<64n)throw Error('El rango desborda 64 bits.');
    return result;
}
/** Exclusive end may equal 2^64; it is never serialized as an address. */
export function end(r:AddressRange):bigint {return offset(r.start)+BigInt(r.size);}
export function contains(r:AddressRange,a:Address):boolean {return r.start.space===a.space&&offset(a)>=offset(r.start)&&offset(a)<end(r);}
export function compare(a:Address,b:Address):number {return a.space===b.space?(offset(a)<offset(b)?-1:offset(a)>offset(b)?1:0):a.space<b.space?-1:1;}
