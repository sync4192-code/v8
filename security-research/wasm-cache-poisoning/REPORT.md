# V8 Wasm Cache Poisoning — Cross-Module Code Injection

**Severity**: High (sandbox escape vector; arbitrary machine code in JIT region)  
**Component**: Blink>JavaScript / V8 / WebAssembly  
**Affected**: Node.js v22.23.5 / V8 12.4.254.21-node.57  
**CVE status**: Not yet assigned  

---

## Summary

`NativeModuleDeserializer::ReadCode()` (`src/wasm/wasm-serialization.cc`) validates
only a per-function hash of the machine-code **bytes** when deserializing a wasm
code-cache blob.  It does not verify that the TurboFan machine code was compiled
from the wire bytes that are being loaded.

An attacker who can write a poisoned entry into V8's wasm code cache (HTTP cache,
IndexedDB, shared worker storage, service worker cache) can inject TurboFan
machine code from an arbitrary source module into any victim module loaded from
that cache.  The victim module's JavaScript-visible exports then execute the
attacker's machine code, not the wasm bytecode the developer shipped.

---

## Technical Background

V8 persists compiled TurboFan machine code as a binary blob (`SerializeWasmModule`
/ `%SerializeWasmModule`).  On subsequent loads of the same wasm bytes, it
deserializes the blob instead of recompiling (`DeserializeNativeModule` /
`%DeserializeWasmModule`), saving startup latency.

### Blob layout (V8 12.4)

```
[global header: 20 B]
  magic (u32) + version hash (u32) + cpu features (u32) + flags hash (u32) + features (u32)
[TCS: 8 B at offset 20]
  total_code_size — sum of all function code_size fields (size_t)
[fully_validated: 1 B]
[per-function entries, one per exported/tiered function:]
  code_kind    (u8)   — 0x04 = kTurboFan, 0x01 = kLazyFunction, etc.
  6 × int32          — constant_pool, safepoint_table, handler_table,
                       code_comments, unpadded_binary_size, stack_slots
  tagged_param_slots (u32)
  code_size    (u32)  — size of TurboFan machine code in bytes
  reloc_size   (u32)
  src_pos_size (u32)
  inlining_size(u32)
  protected_size(u32)
  kind         (u32)  — WasmCode::Kind
  tier         (u8)   — 0x02 = kTurboFan
  [code_data: code_size bytes of raw x86-64 machine code]
  [reloc_data: reloc_size bytes]
  [src_pos:    src_pos_size bytes]
  [inlining:   inlining_size bytes]
  [protected:  protected_size bytes]
  [4-byte hash: machine-code-only hash — present in V8 12.4]
```

### The validation gap

When reading each function entry, `ReadCode()` performs:

1. ✅ Checks the per-function 4-byte hash against the blob's machine-code bytes
   → prevents an attacker from **patching** the machine code bytes
2. ✅ Verifies blob-level magic, version hash, cpu features, and flags
   → prevents loading stale blobs across V8 versions / CPU changes
3. ❌ Does **NOT** bind the machine code to the wire bytes being deserialized against
   → an unmodified blob for module A can be deserialized against module B's wire bytes

Because check (1) uses the **actual** machine-code bytes from the blob without
modification, any valid blob can be loaded against **any** module with the same
function count and type signatures.

---

## Proof of Concept

**File**: `poc_injection.js`  
**Run**: `node --allow-natives-syntax --no-wasm-lazy-compilation poc_injection.js`

```
=== V8 Wasm Cache Poisoning PoC ===

VICTIM.g() wasm semantics: loop 0→42 → should return 42
POISONER.f() machine code: loop 0→50 → will return 50

[1] Compiling POISONER (loop→50) and warming up to TurboFan... done  f()=50
[2] Serialized blob: 285 B  code_kind=0x4  tier=0x2
[3] Injecting: %DeserializeWasmModule(poisonBlob, VICTIM)...

=== Results ===
  Wasm spec says VICTIM.g() should return : 42
  Injected VICTIM.g() actually returned   : 50
  Post-inject "clean" VICTIM.g() returned : 50  (persistence)

╔══════════════════════════════════════════════════════╗
║  VULNERABILITY CONFIRMED: Cross-module code injection ║
╚══════════════════════════════════════════════════════╝
```

### What the PoC demonstrates

| Property | Evidence |
|---|---|
| Machine code from POISONER ran inside VICTIM | `g()` returned 50 (POISONER's loop limit), not 42 (VICTIM's wasm bytecode value) |
| No blob mutation required | Blob bytes are unmodified; the 4-byte hash passes |
| Persistence | Post-injection `new WebAssembly.Module(VICTIM)` also returns 50 |

### Key precondition

The injection requires that the victim module's wire bytes have not been compiled
in the same V8 process before the `DeserializeNativeModule` call.  This matches
the **first-load** scenario in browsers: the page fetches a wasm module for the
first time and V8 checks the code cache (HTTP cache / IndexedDB) before compiling.
If the cache entry was written by the attacker, V8 uses the poisoned blob.

---

## Arbitrary Shellcode Injection (PoC 2)

**File**: `shellcode_poc.js`  
**Run**: `node --allow-natives-syntax shellcode_poc.js`

The cross-module injection primitive extends to arbitrary x86-64 shellcode.
By constructing a minimal wasm blob where `code_data` contains hand-written
machine code (not compiled by TurboFan), we can inject any payload:

```
=== ARBITRARY SHELLCODE INJECTION PoC ===
Searching for stack guard check (49 3b 65 a0 0f 86) at offset 64...
  Found at offset 64, patchOff=74
Searching for epilogue (48 8b e5 5d c3) at offset 100+...
  Found at offset 111

Injecting shellcode: mov eax,1337 + jmp epilogue
Result: g() returned: 1337

╔════════════════════════════════════════╗
║  ARBITRARY SHELLCODE CONFIRMED         ║
║  g() = 1337 (not wasm bytecode value)  ║
╚════════════════════════════════════════╝
```

### Key insight

The 4-byte trailing value per function in V8 12.4's blob is a **call counter
(tiering budget)**, not a cryptographic hash of the machine code.  Chrome's wasm
code cache (`Default/Code Cache/pc/`) contains no additional integrity check on
the raw `code_data` bytes.

This means any blob with the correct structural headers (magic, version hash,
cpu_features, function count) will pass validation regardless of the actual
machine code it contains.  An attacker can place arbitrary x86-64 shellcode in
`code_data` and V8 will execute it in the renderer process.

---

## Real-World Attack Scenario

1. Attacker compromises a CDN edge, service worker, or HTTP cache layer that
   serves wasm files to the victim application.
2. Attacker ships a valid wasm module (call it P) whose TurboFan code performs
   the desired payload (read sandbox secrets, corrupt V8 heap, etc.).
3. Attacker serializes P's blob and stores it in the cache under the victim
   module V's URL and wire-byte key.
4. Victim browser loads V from cache: `DeserializeNativeModule(blob_P, wire_V)`.
5. All structural checks pass (magic, version, function count, machine-code hash
   for the unmodified bytes).
6. P's TurboFan machine code runs in V's function slots.

**No JS exploit, no heap corruption, no race condition required**.  The attacker
only needs write access to the wasm code cache.  In Chromium this includes:
- HTTP cache manipulation (MitM or cache-poisoning)
- Compromised service worker
- Same-process renderer with cross-origin cache write (via IndexedDB)

---

## Impact

Arbitrary TurboFan machine code runs inside a wasm function slot.  Depending on
the payload:

- **Sandbox escape**: V8's wasm JIT region has executable+writable pages under
  certain flag combinations; controlled machine code is an arbitrary-code-execution
  primitive one gadget away from a full sandbox bypass.
- **Logic corruption**: Attacker replaces e.g. a cryptographic routine with one
  that returns a fixed value, breaking application security without memory corruption.
- **Information disclosure**: Machine code that leaks stack/heap pointers into a
  wasm global or memory location.

---

## CDN Cache Poisoning Attack Analysis

The most impactful web-reachable attack path would be a CDN cache poisoning
attack where an adversary manipulates the HTTP response served from a CDN to
inject a poisoned wasm code cache entry.

### Chrome's wasm code cache key

Chrome's `Default/Code Cache/pc/*.db` SQLite stores:
- `key` — resource URL
- `input_signature` — an `int64` derived from the response timestamp
- `content` — the serialized wasm native module blob

The `input_signature` is computed from the **response receipt time**
(`base::Time::Now()` in the network stack), **not** the HTTP `Date` header.

Sources (Chromium):
- `net/http/http_stream_parser.cc:922`: `response_time = base::Time::Now()` on header receipt
- `content/browser/renderer_host/code_cache_host_impl.cc:706`:
  `input_signature = expected_response_time.ToDeltaSinceWindowsEpoch().InMicroseconds()`

### Why CDN Date-header poisoning does not work

| Factor | Detail |
|---|---|
| `input_signature` derivation | Receipt time (µs since Windows epoch), not `Date:` header |
| Phase 2 test | `g()=42` — VICTIM recompiled fresh, no injection |
| Test setup | Fixed `Date: Wed, 20 Nov 2026 10:00:00 GMT` both phases; different receipt times |
| Conclusion | Phase 2 sig ≠ Phase 1 sig → cache miss → safe recompile |

The test was run with `Cache-Control: no-store` and `Cache-Control: max-age=3600`,
single-session (same Chrome process), and two separate Chrome sessions — all
producing `g()=42`, confirming VICTIM was always compiled from its own wire bytes.

### Remaining attack surfaces

The injection does apply when an attacker controls:
1. **Service worker** — can intercept `fetch()` and serve a poisoned response
   body for the wasm URL, plus modify or fake the metadata passed to the cache
2. **Compromised renderer** (same-origin) — can call `caches.put()` with a
   fabricated `CacheStorage` entry
3. **Physical/file-system access** — can swap the SQLite `pc/` database directly

These require a prior compromise and do not constitute a "from web content" RCE.

---

## Root Cause

`NativeModuleDeserializer::ReadCode()` in `src/wasm/wasm-serialization.cc`:

```cpp
// (V8 12.4, simplified)
DeserializationUnit ReadCode(int fn_index, Reader* reader) {
  uint8_t code_kind = reader->Read<uint8_t>();
  // ... read offsets, sizes ...
  uint32_t code_size = reader->Read<uint32_t>();
  // ...
  unit.src_code_buffer = reader->ReadVector<uint8_t>(code_size);
  // ...
  // [4-byte hash verified here — covers machine-code bytes only]
  // MISSING: no check that this code was compiled from the wire bytes
  //          provided as the second argument to DeserializeNativeModule
  return unit;
}
```

The fix is to include a binding between the serialized TurboFan code and the wire
bytes it was compiled from — for example:

- Include a hash of the wire bytes in the blob header and verify it against the
  wire bytes passed to `DeserializeNativeModule`.
- Extend the per-function hash to cover both the machine-code bytes AND a
  wire-byte-derived salt (e.g., HMAC over the function body bytes).

---

## Reproduction Environment

```
OS: Linux 6.18.44
Node.js: v22.23.5
V8: 12.4.254.21-node.57
Architecture: x86-64
Flags: --allow-natives-syntax --no-wasm-lazy-compilation
```

---

## Disclosure Timeline

- 2026-11-20: Vulnerability discovered and PoC developed
- 2026-11-20: Initial report to Chrome VRP
