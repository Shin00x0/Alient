import { test } from 'node:test';
import assert from 'node:assert/strict';
import { layoutCfg } from '../frontend/cfg-layout.ts';

test('CFG layout places branch targets in the next stable layer', () => {
    const layout = layoutCfg([
        { address: '1000', edges: [{ to: '1010', type: 'JUMP' }, { to: '1004', type: 'FALL_THROUGH' }] },
        { address: '1004', edges: [{ to: '1020', type: 'JUMP' }] },
        { address: '1010', edges: [{ to: '1020', type: 'FALL_THROUGH' }] },
        { address: '1020', edges: [] },
    ]);
    assert.equal(layout.get('1000')?.rank, 0);
    assert.equal(layout.get('1004')?.rank, 1);
    assert.equal(layout.get('1010')?.rank, 1);
    assert.equal(layout.get('1020')?.rank, 2);
    assert.notEqual(layout.get('1004')?.x, layout.get('1010')?.x);
});

test('CFG layout does not extend a loop forever', () => {
    const layout = layoutCfg([
        { address: '2000', edges: [{ to: '2004', type: 'FALL_THROUGH' }] },
        { address: '2004', edges: [{ to: '2000', type: 'JUMP' }] },
    ]);
    assert.deepEqual([...layout.values()].map(value => value.rank), [0, 1]);
});
