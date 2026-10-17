// Compare every fixture byte after executing the pure codec in WebAssembly.
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
const [wasm, golden] = process.argv.slice(2);
assert.ok(wasm && golden, 'usage: node check_snapshot_wasm.mjs WASM GOLDEN');
const { instance } = await WebAssembly.instantiate(readFileSync(wasm), {});
const { memory, snapshot_fixture } = instance.exports;
const handle = snapshot_fixture();
const pointer = Number(handle >> 32n);
const length = Number(handle & 0xffffffffn);
const actual = Buffer.from(memory.buffer, pointer, length);
assert.deepEqual(actual, readFileSync(golden));
console.log(`snapshot native/WASM: ${length} bytes, equal`);
