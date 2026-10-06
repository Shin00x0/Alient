import {test} from 'node:test';
import assert from 'node:assert/strict';
import {engineCapabilities,projectEngine} from '../backend/engine/capabilities.ts';
import {tabCapability} from '../frontend/capabilities-view.ts';

test('native projects expose partial C, typed variables and transactional edits',()=>{
    const c=engineCapabilities('internal',false,{status:'ready',persistent:true});
    assert.equal(c.runtimeAvailable,true);assert.equal(c.actions.edit.enabled,true);
    for(const tab of ['types','variables','bookmarks','edit','notes','strings','xref','flow','code-search'])assert.equal(tabCapability(tab,c).enabled,true);
    assert.equal(c.features.cCode.status,'partial');assert.ok(c.editOperations.includes('undo'));assert.ok(c.editOperations.includes('define-type'));
    const missing=engineCapabilities('internal',false,{status:'ready',persistent:true},false);
    assert.equal(missing.actions.edit.enabled,false);assert.equal(missing.actions.analyze.enabled,false);assert.equal(tabCapability('types',missing).enabled,true);
});
test('missing Ghidra runtime blocks mutations but does not hide persisted results',()=>{
    const c=engineCapabilities('ghidra',false,{status:'ready',persistent:true});
    assert.equal(c.actions.analyze.enabled,false);assert.equal(tabCapability('edit',c).enabled,false);
    for(const tab of ['types','variables','bookmarks','notes','code-search'])assert.equal(tabCapability(tab,c).enabled,true);
    assert.equal(c.features.cCode.status,'supported');assert.ok(c.runtimeReason);
});
test('Ghidra edit availability follows project readiness and legacy projects retain Ghidra',()=>{
    assert.equal(projectEngine({}),'ghidra');assert.equal(projectEngine({engine:'internal'}),'internal');
    for(const status of ['queued','analyzing','failed','cancelled'] as const)assert.equal(engineCapabilities('ghidra',true,{status,persistent:true}).actions.edit.enabled,false);
    assert.equal(engineCapabilities('ghidra',true,{status:'ready',persistent:false}).actions.edit.enabled,false);
    const c=engineCapabilities('ghidra',true,{status:'ready',persistent:true});
    assert.equal(c.actions.edit.enabled,true);assert.ok(c.editOperations.includes('signature'));assert.ok(!c.editOperations.includes('patch'));
    assert.deepEqual(JSON.parse(JSON.stringify(c)),c);
});
