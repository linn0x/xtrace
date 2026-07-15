"""Patch-free general API-hook capture via CDP (no Chromium changes).

Injects a generic preamble that wraps standard plaintext-boundary APIs
(TextEncoder/TextDecoder, crypto.subtle, JSON, btoa/atob) BEFORE page scripts,
and streams their inputs/outputs over a CSP-proof CDP binding. Events are written
in an XTrace-compatible NDJSON shape and, after the run, clock-aligned onto the
native trace's monotonic clock and appended, so sign_pipeline reads one trace.

Complements the native V8/Blink hooks (which see through JSVMP): this layer is
portable and gives digest/AES plaintext directly, but is JS-level (evadable, and
blind to code that grabs pristine refs first or runs in unhooked workers).
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import socket
import struct
import time

BINDING = "__xtrace_emit"

# Generic API-wrapping preamble template. Site-neutral: wraps standard web APIs
# only. __SCAN_DELAY_MS__ is filled in by build_preamble().
_PREAMBLE_TMPL = r"""
(() => {
  if (window.__xtrace_injected) return;
  window.__xtrace_injected = true;
  const B = __XTRACE_BINDING__;
  const _stringify = JSON.stringify;   // pristine ref, captured before wrapping
  let _busy = false;                   // re-entrancy guard: emit must not self-log
  const emit = (api, args) => {
    if (_busy) return;
    _busy = true;
    try {
      let cs = "", cf = "";
      const st = (new Error().stack || "").split("\n").slice(2);
      for (const line of st) {
        const m = line.match(/(?:at\s+)?(.*?)\s*\(?(https?:\/\/[^\s):]+)/);
        if (m) { cf = (m[1] || "").trim(); cs = m[2]; break; }
      }
      window[B](_stringify({
        category: "inject", t: "call", api, args,
        wall_time_us: Date.now() * 1000,
        callsite_function: cf, callsite_script: cs,
      }));
    } catch (e) {}
    _busy = false;
  };
  const CAP = __CAP__;   // hot-path values (crypto I/O) are kept whole up to CAP
  const preview = (v) => {
    try {
      if (typeof v === "string") return { type: "string", len: v.length, value: v.slice(0, CAP) };
      if (v instanceof ArrayBuffer) v = new Uint8Array(v);
      if (ArrayBuffer.isView(v)) {
        const u = new Uint8Array(v.buffer, v.byteOffset, Math.min(v.byteLength, CAP));
        let hex = ""; for (const b of u) hex += b.toString(16).padStart(2, "0");
        return { type: v.constructor.name, byteLength: v.byteLength, hex };
      }
      if (v && typeof v === "object") return { type: v.constructor ? v.constructor.name : "object" };
      return { type: typeof v, value: String(v).slice(0, CAP) };
    } catch (e) { return { type: "?" }; }
  };
  const wrap = (obj, name, api, ret) => {
    if (!obj) return;
    const orig = obj[name];
    if (typeof orig !== "function") return;
    obj[name] = function (...a) {
      emit(api, a.map(preview));
      const r = orig.apply(this, a);
      // Hot-path outputs: for crypto.subtle the result Promise resolves to the
      // digest / signature / ciphertext bytes -- the reproducible intermediate
      // value replay/oracle needs. Observe it with a spur .then that never alters
      // the chain the page sees, and emit an <api>.ret event.
      if (ret && r && typeof r.then === "function") {
        try { r.then((v) => emit(api + ".ret", [preview(v)]), () => {}); } catch (e) {}
      }
      return r;
    };
    try { obj[name].toString = () => orig.toString(); } catch (e) {}
  };
  wrap(window.TextEncoder && TextEncoder.prototype, "encode", "TextEncoder.encode");
  wrap(window.TextDecoder && TextDecoder.prototype, "decode", "TextDecoder.decode");
  if (window.crypto && crypto.subtle) {
    for (const m of ["digest", "sign", "verify", "encrypt", "decrypt", "importKey", "deriveBits"]) {
      wrap(crypto.subtle, m, "SubtleCrypto." + m, true);   // also capture the output bytes
    }
  }
  wrap(JSON, "stringify", "JSON.stringify");
  wrap(JSON, "parse", "JSON.parse");
  wrap(window, "btoa", "btoa");
  wrap(window, "atob", "atob");

  // JS-implemented hash/cipher (e.g. CryptoJS) reads its message char-by-char
  // via charCodeAt (Utf8.parse); crypto.subtle is not used. Capture the full
  // scanned plaintext once per distinct string -- the digest/AES INPUT for the
  // JS-crypto path (native summary mode refs long strings, losing it).
  //
  // Performance (lessons from heavy production SPAs):
  // 1) Only materialize when i===0 (Utf8.parse always starts at 0). Copying the
  //    whole string on every char is O(L^2).
  // 2) A permanent JS wrapper on every charCodeAt of a 40k string is still ~L
  //    JS calls and starves the SPA. After capturing at i===0, hand the rest of
  //    the synchronous scan back to *native* charCodeAt and re-hook on a
  //    microtask (CryptoJS Utf8.parse is fully sync).
  // 3) Delay install a few seconds so the page can hydrate first.
  const SCAN_CAP = __SCAN_CAP__, SCAN_MIN = 24, SCAN_DELAY_MS = __SCAN_DELAY_MS__;
  setTimeout(() => {
    const orig = String.prototype.charCodeAt;
    let _lastScan = null;
    let _pending = false;
    const hooked = function (i) {
      if ((i | 0) === 0) {
        const len = this.length;
        if (len >= SCAN_MIN) {
          const s = "" + this;
          if (s !== _lastScan) {
            _lastScan = s;
            emit("String.scan", [{ type: "string", len, value: s.slice(0, SCAN_CAP) }]);
          }
        }
        // Fast-path the remainder of this sync Utf8.parse: native loop, then
        // re-arm the hook after the current turn (covers the next message).
        String.prototype.charCodeAt = orig;
        if (!_pending) {
          _pending = true;
          queueMicrotask(() => {
            _pending = false;
            String.prototype.charCodeAt = hooked;
          });
        }
      }
      return orig.call(this, i);
    };
    try { hooked.toString = () => orig.toString(); } catch (e) {}
    String.prototype.charCodeAt = hooked;
  }, SCAN_DELAY_MS);

  // WASM boundary: per-call JS<->WASM I/O (imports = WASM->JS callbacks,
  // exports = JS->WASM calls). This is the per-call visibility the native V8
  // boundary hooks cannot give. Instruction-level internals would need binary
  // rewriting; here we wrap the JS-visible boundary of each instance.
  if (window.WebAssembly) {
    const WA = WebAssembly;
    const wrapImports = (imp) => {
      if (!imp || typeof imp !== "object") return imp;
      const out = {};
      for (const ns of Object.keys(imp)) {
        const m = imp[ns];
        if (m && typeof m === "object") {
          const o = {};
          for (const k of Object.keys(m)) {
            const v = m[k];
            o[k] = (typeof v === "function") ? function (...a) {
              emit("WebAssembly.import", [{ ns, name: k }].concat(a.map(preview)));
              return v.apply(this, a);
            } : v;
          }
          out[ns] = o;
        } else out[ns] = m;
      }
      return out;
    };
    const wrapInstance = (inst) => {
      try {
        // WASM export props are read-only + non-configurable, so a Proxy get()
        // returning a different fn violates a Proxy invariant. Build a plain
        // wrapped-exports object instead; keep instanceof + other access via proto.
        const ex = inst.exports;
        const wrapped = {};
        for (const k of Object.keys(ex)) {
          const v = ex[k];
          wrapped[k] = (typeof v === "function") ? function (...a) {
            emit("WebAssembly.export", [{ name: k }].concat(a.map(preview)));
            const r = v.apply(ex, a);
            emit("WebAssembly.export.ret", [{ name: k }, preview(r)]);
            return r;
          } : v;
        }
        return Object.create(inst, { exports: { value: wrapped, enumerable: true } });
      } catch (e) { return inst; }
    };
    const oInst = WA.instantiate;
    WA.instantiate = function (src, imp, ...rest) {
      const r = oInst.call(this, src, wrapImports(imp), ...rest);
      return (r && r.then) ? r.then((res) => (res && res.instance)
        ? { module: res.module, instance: wrapInstance(res.instance) }
        : wrapInstance(res)) : r;
    };
    if (WA.instantiateStreaming) {
      const oStream = WA.instantiateStreaming;
      WA.instantiateStreaming = function (src, imp, ...rest) {
        return oStream.call(this, src, wrapImports(imp), ...rest)
          .then((res) => ({ module: res.module, instance: wrapInstance(res.instance) }));
      };
    }
    const OInstance = WA.Instance;
    WA.Instance = function (mod, imp) {
      return wrapInstance(new OInstance(mod, wrapImports(imp)));
    };
    WA.Instance.prototype = OInstance.prototype;
  }
})();
""".replace("__XTRACE_BINDING__", json.dumps(BINDING))


def build_preamble(scan_delay_ms: int = 4000, scan_cap: int = 4096,
                   cap: int | None = None) -> str:
    """Preamble with the String.scan install delay (ms) and value caps filled in.

    ``cap`` bounds every captured boundary value -- crypto.subtle / TextEncoder /
    JSON / btoa inputs, crypto.subtle *outputs*, and typed-array hex bytes -- and
    defaults to ``scan_cap`` so one knob governs how much of a hot-path value is
    kept whole. ``len`` / ``byteLength`` always carry the true size, so downstream
    truncation detection (sign_pipeline's cap_hint) still fires if a value clips."""
    if cap is None:
        cap = scan_cap
    return (_PREAMBLE_TMPL
            .replace("__SCAN_DELAY_MS__", str(int(scan_delay_ms)))
            .replace("__SCAN_CAP__", str(int(scan_cap)))
            .replace("__CAP__", str(int(cap))))


PREAMBLE = build_preamble()  # default; run_injector rebuilds with the CLI delay


class _WS:
    """Minimal RFC6455 text-frame client (stdlib only) for CDP over websocket."""

    def __init__(self, url: str):
        assert url.startswith("ws://"), url
        hostport, _, path = url[len("ws://"):].partition("/")
        host, _, port = hostport.partition(":")
        self.sock = socket.create_connection((host, int(port or 80)))
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET /{path} HTTP/1.1\r\nHost: {hostport}\r\n"
               f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.sock.sendall(req.encode())
        self._buf = b""
        while b"\r\n\r\n" not in self._buf:
            self._buf += self.sock.recv(4096)
        head, self._buf = self._buf.split(b"\r\n\r\n", 1)
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise ConnectionError(f"ws handshake failed: {head[:80]!r}")

    def send(self, text: str):
        payload = text.encode("utf-8")
        header = bytearray([0x81])
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        mask = os.urandom(4)
        header += mask
        self.sock.sendall(bytes(header) + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def _read(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("ws closed")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def recv(self) -> str:
        data = b""
        while True:
            b0, b1 = self._read(2)
            opcode = b0 & 0x0F
            ln = b1 & 0x7F
            if ln == 126:
                ln = struct.unpack(">H", self._read(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", self._read(8))[0]
            if b1 & 0x80:
                mask = self._read(4)
                payload = bytes(c ^ mask[i % 4] for i, c in enumerate(self._read(ln)))
            else:
                payload = self._read(ln)
            if opcode == 0x8:
                raise ConnectionError("ws close frame")
            if opcode == 0x9:  # ping -> ignore (Chromium rarely pings)
                continue
            data += payload
            if b0 & 0x80:  # FIN
                return data.decode("utf-8", "replace")

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def find_page_ws(port: int, timeout: float = 20.0):
    """Poll the CDP HTTP endpoint for a page target's webSocketDebuggerUrl."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
            conn.request("GET", "/json/list")
            targets = json.loads(conn.getresponse().read())
            for t in targets:
                if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                    return t["webSocketDebuggerUrl"]
        except (OSError, ValueError):
            pass
        time.sleep(0.4)
    return None


def run_injector(port: int, target_url: str, out_path, stop_event,
                 scan_delay_ms: int = 4000, scan_cap: int = 4096):
    """Connect to the page target, install the preamble + binding, navigate, and
    stream binding events to out_path (NDJSON). Blocks until stop_event/teardown.

    Returns the number of injected events written."""
    ws_url = find_page_ws(port)
    if not ws_url:
        return 0
    ws = _WS(ws_url)
    n = [0]

    def cmd(method, params=None):
        cmd.i += 1
        ws.send(json.dumps({"id": cmd.i, "method": method, "params": params or {}}))
    cmd.i = 0

    cmd("Runtime.enable")
    cmd("Page.enable")
    cmd("Runtime.addBinding", {"name": BINDING})
    cmd("Page.addScriptToEvaluateOnNewDocument",
        {"source": build_preamble(scan_delay_ms, scan_cap)})
    cmd("Page.navigate", {"url": target_url})

    with open(out_path, "w", encoding="utf-8") as fh:
        while not stop_event.is_set():
            try:
                msg = ws.recv()
            except (OSError, ConnectionError):
                break
            try:
                m = json.loads(msg)
            except ValueError:
                continue
            if m.get("method") == "Runtime.bindingCalled":
                p = m.get("params", {})
                if p.get("name") == BINDING and p.get("payload"):
                    # Page strings may contain lone surrogates; keep file UTF-8-safe.
                    payload = p["payload"]
                    if isinstance(payload, str):
                        payload = payload.encode("utf-8", "surrogatepass").decode(
                            "utf-8", "replace"
                        )
                    fh.write(payload + "\n")
                    n[0] += 1
    ws.close()
    return n[0]


def _sanitize_for_json(obj):
    """Drop lone surrogates from injected strings (page data can be ill-formed UTF-16)."""
    if isinstance(obj, str):
        return obj.encode("utf-8", "surrogatepass").decode("utf-8", "replace")
    if isinstance(obj, list):
        return [_sanitize_for_json(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): _sanitize_for_json(v) for k, v in obj.items()}
    return obj


def _dumps_event(e) -> str:
    """Serialize inject events without crashing on surrogate code points.

    Always sanitize first: json.dumps(..., ensure_ascii=False) can succeed while
    still embedding lone surrogates that later fail on utf-8 file write.
    """
    return json.dumps(_sanitize_for_json(e), ensure_ascii=False, default=str)


def align_and_append(native_trace, injected_path):
    """Stamp injected events with a monotonic clock derived from the native trace's
    (mono_time_us, wall_time_us) pairs, then append them to the native trace so a
    single NDJSON carries both. Returns the number of events appended."""
    native_trace, injected_path = str(native_trace), str(injected_path)
    if not (os.path.exists(native_trace) and os.path.exists(injected_path)):
        return 0
    offsets, seq, has_global_seq = [], 0, False
    with open(native_trace, encoding="utf-8") as fh:
        for line in fh:
            if '"wall_time_us"' not in line or '"mono_time_us"' not in line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            mono, wall = e.get("mono_time_us"), e.get("wall_time_us")
            gs = e.get("global_seq")
            if isinstance(gs, int):
                has_global_seq = True
                seq = max(seq, gs)
            if isinstance(mono, (int, float)) and isinstance(wall, (int, float)) and wall > 1e12:
                offsets.append(mono - wall)
    if not offsets:
        return 0
    offsets.sort()
    offset = offsets[len(offsets) // 2]  # median mono-wall offset (~constant)

    # Injected bindings run in the renderer but do not use the native logger,
    # so give their records a distinct, trace-stable producer session.  Do not
    # reuse the native session_id/seq: those are already meaningful within the
    # native producer and may span more than one renderer process.
    session_id = "inject:" + hashlib.sha256(
        os.path.abspath(native_trace).encode("utf-8")
    ).hexdigest()[:16]
    appended = 0
    with open(injected_path, encoding="utf-8", errors="replace") as src, \
            open(native_trace, "a", encoding="utf-8") as dst:
        for line in src:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                continue
            wall = e.get("wall_time_us")
            if not isinstance(wall, (int, float)):
                # A binding event without a wall clock cannot be aligned or
                # satisfy the trace's ordering contract, so omit it rather
                # than append a malformed partial record.
                continue
            e["mono_time_us"] = wall + offset
            seq += 1
            appended += 1
            phase = e.get("phase") or e.get("t") or "call"
            e["schema_version"] = 1
            e["session_id"] = session_id
            e["seq"] = appended
            e["session_seq"] = appended
            e["event_id"] = f"{session_id}:{appended}"
            e["t"] = phase
            e["ts"] = wall
            if has_global_seq:
                e["global_seq"] = seq
            e["phase"] = phase
            e.setdefault("stack", [])
            e.setdefault("pid", 0)
            e.setdefault("tid", 0)
            e.setdefault("frame_url", "")
            e.setdefault("origin", "")
            e.setdefault("result", None)
            e.setdefault("error", None)
            e.setdefault("truncated", False)
            dst.write(_dumps_event(e) + "\n")
    return appended
