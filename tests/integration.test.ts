import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';
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
    try {
        const health = await (await fetch(base + '/api/health')).json();
        assert.equal(health.engine, 'ready', 'Requires GHIDRA_HOME/JAVA_HOME or .runtime');
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
        console.log(`Verified ${result.functions.length} real functions; ${result.language}. Test data: ${data}`);
    }
    finally {
        await stop(child);
    }
});
