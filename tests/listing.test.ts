import {test} from 'node:test';
import assert from 'node:assert/strict';
import {locatePage,readListing} from '../backend/listing.ts';
import {mkdtemp,mkdir,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import type {ListingManifest} from '../backend/types.ts';
test('listing seeks 64-bit addresses, gaps and memory spaces without numeric precision loss',()=>{
 const index:ListingManifest={generation:'',totalInstructions:3,pageSize:256,defaultSpace:'ram',pages:[{page:0,space:'ram',start:'ffffffffffffff00',end:'ffffffffffffff0f',count:1},{page:1,space:'ram',start:'ffffffffffffff80',end:'ffffffffffffffff',count:1},{page:2,space:'overlay',start:'1000',end:'1003',count:1}]};
 assert.equal(locatePage(index,'ffffffffffffff03').page,0);
 assert.equal(locatePage(index,'ffffffffffffff50').page,1);
 assert.equal(locatePage(index,'ffffffffffffffff').page,1);
 assert.equal(locatePage(index,'overlay:0x1001').page,2);
 assert.throws(()=>locatePage(index,'hello!'));
 assert.throws(()=>locatePage(index,'other:1000'));
});
test('listing resolves instruction interiors and nearest rows, rejects invalid pages and supports empty programs',async()=>{
 const root=await mkdtemp(join(tmpdir(),'listing-unit-')),generation='listing-11111111-1111-1111-1111-111111111111',dir=join(root,generation);await mkdir(dir);
 const index={generation,totalInstructions:2,pageSize:256,defaultSpace:'ram',pages:[{page:0,space:'ram',start:'1000',end:'1013',count:2}]};
 await writeFile(join(dir,'index.json'),JSON.stringify(index));await writeFile(join(dir,'0.json'),JSON.stringify([{address:'1000',offset:'1000',endOffset:'1003'},{address:'1010',offset:'1010',endOffset:'1013'}]));
 const interior=await readListing(root,generation,new URLSearchParams({address:'1002'}));assert.equal(interior.exact,true);assert.equal(interior.selected,'1000');
 const gap=await readListing(root,generation,new URLSearchParams({address:'1008'}));assert.equal(gap.exact,false);assert.equal(gap.selected,'1010');
 await assert.rejects(readListing(root,generation,new URLSearchParams({page:'-1'})));
 await assert.rejects(readListing(root,generation,new URLSearchParams({page:'1'})));
 await assert.rejects(readListing(root,'../../',new URLSearchParams()));
 await writeFile(join(dir,'index.json'),JSON.stringify({...index,totalInstructions:0,pages:[]}));assert.equal((await readListing(root,generation,new URLSearchParams())).rows.length,0);
});
