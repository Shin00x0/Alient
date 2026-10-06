import {test} from 'node:test';
import assert from 'node:assert/strict';
import {sameAddress,inRange,stringReferences} from '../frontend/explorer.ts';
test('64-bit address navigation preserves precision and string xrefs include interior addresses',()=>{
    assert.ok(sameAddress('00001000','0x1000'));
    assert.ok(!sameAddress('ffffffffffffffff','fffffffffffffffe'));
    assert.ok(inRange('fffffffffffffffe','fffffffffffffffc','ffffffffffffffff'));
    assert.ok(!inRange('EXTERNAL:0001','1000','2000'));
    const refs=[{from:'1010',to:'2000',type:'DATA',call:false},{from:'1020',to:'2004',type:'DATA',call:false},{from:'1030',to:'2010',type:'DATA',call:false}];
    assert.equal(stringReferences(refs,'2000','2009').length,2);
});
