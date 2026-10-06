import {parentPort,workerData} from 'node:worker_threads';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {writeInternalAnalysis} from './index.ts';
try {await writeInternalAnalysis(await readFile(join(workerData.directory,'input.bin')),workerData.name,workerData.directory);parentPort!.postMessage({ok:true});}
catch(error){parentPort!.postMessage({ok:false,error:error instanceof Error?error.message:String(error)});}
