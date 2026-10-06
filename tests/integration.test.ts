import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';
import { stringReferences } from '../frontend/explorer.ts';
import { markupText } from '../frontend/code-view.ts';
import type { FunctionInfo } from '../backend/types.ts';
const port = 4311, base = `http://127.0.0.1:${port}`;
const wait = (ms: number) => new Promise(r => setTimeout(r, ms));
async function start(data: string) { const child = spawn(process.execPath, ['--experimental-strip-types', 'backend/server.ts'], { env: { ...process.env, PORT: String(port), DATA_DIR: data }, stdio: 'pipe' }); let logs = ''; child.stderr?.on('data', b => logs += b); for (let n = 0; n < 50; n++) {
    try {
        const r = await fetch(base + '/api/health');
        if (r.ok)
            return child;
    }
    catch { }
    if (child.exitCode !== null)
        throw Error(logs);
    await wait(100);
} child.kill(); throw Error('Server did not start: ' + logs); }
async function stop(child: ChildProcess) { await new Promise<void>(resolve => { child.once('exit', () => resolve()); child.kill('SIGINT'); }); }
test('real Ghidra analysis, bytes, annotations, persistence and API boundaries', { timeout: 180000 }, async () => {
    const data = await mkdtemp(join(tmpdir(), 'ghidra-web-test-'));
    let child = await start(data);
    let succeeded=false;
    try {
        const health = await (await fetch(base + '/api/health')).json();
        assert.equal(health.ghidraAvailable, true, 'Requires GHIDRA_HOME/JAVA_HOME or .runtime');
        assert.equal((await fetch(base+'/api/settings',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({engine:'ghidra'})})).status,200);
        assert.equal((await fetch(base + '/api/projects', { headers: { Origin: 'https://example.com' } })).status, 403);
        assert.equal((await fetch(base + '/api/projects', { method: 'POST', body: new Uint8Array() })).status, 400);
        const file = await readFile('fixtures/sample-macho');
        const response = await fetch(base + '/api/projects?name=sample-macho', { method: 'POST', body: file });
        assert.equal(response.status, 202);
        const initial = await response.json();
        let project = initial;
        for (let n = 0; n < 140 && ['queued', 'analyzing'].includes(project.status); n++) {
            await wait(1000);
            project = await (await fetch(base + '/api/projects/' + initial.id)).json();
        }
        assert.equal(project.status, 'ready', project.error + '\n' + project.log);
        const result = await (await fetch(base + '/api/projects/' + initial.id + '/result')).json();
        assert.equal(result.schemaVersion, 4);
        const capabilities=await(await fetch(base+'/api/projects/'+initial.id+'/capabilities')).json();
        assert.equal((await fetch(base+'/api/projects/'+initial.id+'/program')).status,422);
        assert.equal(capabilities.engine,'ghidra');assert.equal(capabilities.actions.edit.enabled,true);assert.equal(capabilities.features.cCode.status,'supported');
        assert.equal(result.engineVersion, '12.1.3');
        assert.equal(result.decompileTimeout, 30);
        for (const fn of result.functions as FunctionInfo[]) {
            if (!fn.code) continue;
            assert.ok(fn.codeLines?.length);
            assert.equal(markupText(fn.codeLines!), fn.code, 'Semantic markup must preserve Ghidra text byte for byte');
            assert.ok(fn.codeLines!.some(line => line.tokens.some(t => t.syntax !== 8)));
        }
        const score = result.functions.find((f: {
            name: string;
        }) => f.name.includes('calculate_score'));
        assert.ok(score, 'Recognizes named function');
        assert.match(score.code, /[+*]/, 'Real decompilation contains arithmetic');
        assert.ok(score.instructions.length > 0);
        assert.ok(result.blocks.length > 0);
        assert.ok(result.strings.some((s: {
            value: string;
        }) => s.value.includes('Ghidra Web static analysis fixture')));
        const bytes = await (await fetch(base + '/api/projects/' + initial.id + '/bytes')).json();
        assert.deepEqual(bytes.bytes, [...file.subarray(0, 256)]);
        assert.equal((await fetch(base + '/api/projects/' + initial.id + '/bytes?offset=-1')).status, 400);
        const annotation = { address: score.address, label: 'score_reviewed', comment: 'Verified persistent note' };
        const saved = await fetch(base + '/api/projects/' + initial.id + '/annotations', { method: 'PUT', body: JSON.stringify(annotation) });
        assert.equal(saved.status, 200);
        assert.equal((await fetch(base + '/api/projects/' + initial.id + '/annotations', { method: 'PUT', body: JSON.stringify({ ...annotation, address: 'bad/address' }) })).status, 400);
        await stop(child);
        child = await start(data);
        const reopened = await (await fetch(base + '/api/projects/' + initial.id)).json();
        assert.equal(reopened.status, 'ready');
        assert.equal(reopened.annotations[score.address].comment, annotation.comment);
        assert.equal(reopened.sha256, initial.sha256);
        const regenerate = await fetch(base + '/api/projects/' + initial.id + '/reanalyze', {method:'POST'});
        assert.equal(regenerate.status, 202);
        assert.equal((await fetch(base + '/api/projects/' + initial.id + '/reanalyze', {method:'POST'})).status, 409);
        project = await regenerate.json();
        for (let n=0;n<140 && ['queued','analyzing'].includes(project.status);n++) {
            await wait(1000);
            project = await (await fetch(base + '/api/projects/' + initial.id)).json();
        }
        assert.equal(project.status, 'ready', project.error + '\n' + project.log);
        assert.equal(project.annotations[score.address].comment, annotation.comment);
        const regenerated = await (await fetch(base + '/api/projects/' + initial.id + '/result')).json();
        assert.equal(regenerated.functions.find((f:FunctionInfo)=>f.address===score.address).code,score.code);
        assert.ok(project.persistent, 'Ghidra database must persist after analysis');
        assert.ok(result.symbols.length>0);
        assert.ok(result.types.length>0);
        assert.ok(score.flowBlocks.length>0);
        const literal=result.strings.find((s:{value:string})=>s.value.includes('Ghidra Web static analysis fixture'));
        assert.ok(stringReferences(result.allReferences,literal.address,literal.end).length>0, 'String has real incoming xrefs');
        const byteMatches=await (await fetch(base+'/api/projects/'+initial.id+'/byte-search?pattern='+file.subarray(0,4).toString('hex').match(/../g)!.join('%20'))).json();
        assert.ok(byteMatches.offsets.includes(0));
        assert.equal((await fetch(base+'/api/projects/'+initial.id+'/byte-search?pattern=ZZ')).status,400);
        async function edit(command:Record<string,string>,expectError=false) {
            const response=await fetch(base+'/api/projects/'+initial.id+'/edit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(command)});
            assert.equal(response.status,202,await response.clone().text());
            let state=await response.json();
            for(let n=0;n<100 && ['queued','analyzing'].includes(state.status);n++){await wait(500);state=await (await fetch(base+'/api/projects/'+initial.id)).json();}
            assert.equal(state.status,'ready',state.error+'\n'+state.log);
            if(expectError)assert.match(state.error,/Cambio rechazado/);else assert.ok(!state.error,state.error);
            return (await (await fetch(base+'/api/projects/'+initial.id+'/result')).json());
        }
        let edited=await edit({operation:'rename',address:score.address,value:'calculate_score_reviewed'});
        assert.equal(edited.functions.find((f:FunctionInfo)=>f.address===score.address).name,'calculate_score_reviewed');
        assert.ok(edited.functions.some((f:FunctionInfo)=>f.code.includes('calculate_score_reviewed')));
        edited=await edit({operation:'signature',address:score.address,value:'int calculate_score_reviewed(int value)'});
        assert.match(edited.functions.find((f:FunctionInfo)=>f.address===score.address).code,/int calculate_score_reviewed\(int value\)/);
        let editedScore=edited.functions.find((f:FunctionInfo)=>f.address===score.address);
        const parameter=editedScore.variables.find((v:{parameter:boolean})=>v.parameter);
        assert.ok(parameter);
        edited=await edit({operation:'variable',address:score.address,value:'input_value',variableId:parameter.id});
        editedScore=edited.functions.find((f:FunctionInfo)=>f.address===score.address);
        assert.match(editedScore.code,/input_value/);
        edited=await edit({operation:'comment',address:score.instructions[0].address,value:'Instruction comment persisted'});
        assert.equal(edited.functions.find((f:FunctionInfo)=>f.address===score.address).instructions[0].comment,'Instruction comment persisted');
        edited=await edit({operation:'function-comment',address:score.address,value:'Function comment persisted'});
        assert.equal(edited.functions.find((f:FunctionInfo)=>f.address===score.address).comment,'Function comment persisted');
        edited=await edit({operation:'bookmark',address:score.address,value:'Review arithmetic'});
        assert.ok(edited.bookmarks.some((b:{comment:string})=>b.comment==='Review arithmetic'));
        await edit({operation:'rename',address:score.address,value:''},true);
        await stop(child);child=await start(data);
        const reopenedEdit=await (await fetch(base+'/api/projects/'+initial.id+'/result')).json();
        assert.match(reopenedEdit.functions.find((f:FunctionInfo)=>f.address===score.address).code,/input_value/);
        const listingBefore=await (await fetch(base+'/api/projects/'+initial.id+'/listing?address='+score.address)).json();
        assert.ok(listingBefore.exact,JSON.stringify(listingBefore));
        assert.equal(listingBefore.rows.find((r:{address:string})=>r.address===score.address).function,'calculate_score_reviewed');
        assert.equal(listingBefore.rows.find((r:{address:string})=>r.address===score.address).comment,'Instruction comment persisted');
        assert.equal((await fetch(base+'/api/projects/'+initial.id+'/listing?page=-1')).status,400);
        const largeUpload=await fetch(base+'/api/projects?name=listing-large-macho',{method:'POST',body:await readFile('fixtures/listing-large-macho')});
        assert.equal(largeUpload.status,202);let large=await largeUpload.json();
        for(let n=0;n<140&&['queued','analyzing'].includes(large.status);n++){await wait(500);large=await(await fetch(base+'/api/projects/'+large.id)).json();}
        assert.equal(large.status,'ready',large.error+'\n'+large.log);
        const listing=await(await fetch(base+'/api/projects/'+large.id+'/listing')).json();
        assert.ok(listing.totalInstructions>=1431, 'More than 1200 instructions and 230 extra functions');
        const allRows=[];
        for(let page=0;page<listing.totalPages;page++){
            const data=await(await fetch(base+'/api/projects/'+large.id+'/listing?page='+page)).json();
            assert.ok(data.rows.length<=256);allRows.push(...data.rows);
        }
        assert.equal(allRows.length,listing.totalInstructions);assert.equal(new Set(allRows.map(r=>r.address)).size,allRows.length);
        const afterLimit=allRows[900];
        const sought=await(await fetch(base+'/api/projects/'+large.id+'/listing?address='+afterLimit.address)).json();
        assert.ok(sought.exact);assert.ok(sought.rows.some((r:{address:string})=>r.address===afterLimit.address));
        assert.ok(new Set(allRows.map(r=>r.functionAddress).filter(Boolean)).size>200,'Listing includes functions beyond decompiler export cap');
        const directory=await(await fetch(base+'/api/projects/'+large.id+'/listing-functions')).json();assert.ok(directory.length>200);assert.ok(directory.some((f:{name:string})=>f.name.includes('listing_part_229')));
        const late=directory.find((f:{name:string})=>f.name.includes('listing_part_229'));
        const largeInitial=await(await fetch(base+'/api/projects/'+large.id+'/result')).json();
        assert.ok(!largeInitial.functions.some((f:{address:string})=>f.address===late.address));
        const endpoint=base+'/api/projects/'+large.id+'/decompile?address='+late.address;
        const responses=await Promise.all([fetch(endpoint),fetch(endpoint)]);
        for(const response of responses)assert.equal(response.status,200);
        const decompiled=await responses[0].json();
        assert.equal(decompiled.address,late.address);assert.equal(decompiled.decompileStatus,'complete');assert.ok(decompiled.code.includes('listing_part_229'));
        assert.deepEqual(await responses[1].json(),decompiled);
        assert.deepEqual(await(await fetch(endpoint)).json(),decompiled);
        assert.equal((await fetch(base+'/api/projects/'+large.id+'/decompile?address=invalid')).status,404);
        assert.equal((await(await fetch(base+'/api/projects/'+large.id)).json()).status,'ready');

        console.log(`Verified full listing: ${listing.totalInstructions} instructions across ${listing.totalPages} pages`);
        const cppUpload = await fetch(base + '/api/projects?name=pseudocode-macho', {method:'POST',body:await readFile('fixtures/pseudocode-macho')});
        assert.equal(cppUpload.status,202);
        let cppProject = await cppUpload.json();
        for(let n=0;n<140 && ['queued','analyzing'].includes(cppProject.status);n++) {
            await wait(1000);
            cppProject = await (await fetch(base + '/api/projects/' + cppProject.id)).json();
        }
        assert.equal(cppProject.status,'ready',cppProject.error + '\n' + cppProject.log);
        const cppResult = await (await fetch(base + '/api/projects/' + cppProject.id + '/result')).json();
        const cppText = cppResult.functions.map((f:FunctionInfo)=>f.code).join('\n');
        assert.match(cppText,/ghidra_web_fixture::score/, 'C++ namespace and function must be demangled by Ghidra');
        for(const fn of cppResult.functions as FunctionInfo[]) if(fn.code) assert.equal(markupText(fn.codeLines!),fn.code);
        succeeded=true;
        console.log(`Verified ${result.functions.length} real functions; ${result.language}`);
    }
    finally {
        await stop(child);
        if(succeeded)await rm(data,{recursive:true,force:true});
    }
});
