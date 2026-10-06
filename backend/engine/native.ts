/** The internal engine is a standalone Rust process. No Java/Ghidra or TS decoder fallback. */
import {spawn} from 'node:child_process';
import {existsSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {resolve,dirname,join} from 'node:path';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'../..');
export const nativeBinary=process.env.NATIVE_ENGINE || ['release','debug'].map(mode=>join(root,'engine-rust','target',mode,'ghidra-web-engine')).find(existsSync) || join(root,'engine-rust','target','release','ghidra-web-engine');
export const nativeAvailable=()=>existsSync(nativeBinary);
export async function nativeQuery(args:string[]):Promise<unknown>{
    return new Promise((resolve,reject)=>{
        const child=spawn(nativeBinary,args,{stdio:['ignore','pipe','pipe']});
        let out='',err='';
        const timer=setTimeout(()=>{child.kill('SIGKILL');reject(Error('Consulta nativa agotó el tiempo.'));},30000);
        child.stdout.on('data',b=>{out+=b;if(out.length>64*1024*1024){child.kill('SIGKILL');reject(Error('Resultado demasiado grande'));}});
        child.stderr.on('data',b=>err=(err+b).slice(-8000));
        child.on('error',e=>{clearTimeout(timer);reject(e);});
        child.on('close',code=>{clearTimeout(timer);try{if(code!==0)throw Error(err||'Error del motor nativo');resolve(JSON.parse(out));}catch(e){reject(e);}});
    });
}
