import Java from "frida-java-bridge";

const CAP = 4096;
let SEQ = 0;
const active = new Set<number>();                 // thread-ids currently inside a hook body

function clip(s: string): string { return s.length > CAP ? s.slice(0, CAP) : s; }

function hexJS(v: any, n: number): string {
  let s = "";
  for (let i = 0; i < n; i++) { const b = v[i] & 0xff; s += (b < 16 ? "0" : "") + b.toString(16); }
  return s;
}

function utf8JS(v: any, n: number): string | null {
  // manual UTF-8 decode of signed bytes; return null on any invalid sequence
  let out = "", i = 0;
  while (i < n) {
    const b0 = v[i] & 0xff;
    if (b0 < 0x80) { out += String.fromCharCode(b0); i += 1; continue; }
    let cp: number, len: number;
    if (b0 >= 0xc2 && b0 <= 0xdf) { cp = b0 & 0x1f; len = 2; }
    else if (b0 >= 0xe0 && b0 <= 0xef) { cp = b0 & 0x0f; len = 3; }
    else if (b0 >= 0xf0 && b0 <= 0xf4) { cp = b0 & 0x07; len = 4; }
    else return null;
    if (i + len > n) return null;
    for (let k = 1; k < len; k++) { const bk = v[i + k] & 0xff; if (bk < 0x80 || bk > 0xbf) return null; cp = (cp << 6) | (bk & 0x3f); }
    out += String.fromCodePoint(cp); i += len;
  }
  return out;
}

function describe(v: any): any {
  if (v === null || v === undefined) return null;
  if (typeof v !== "object") return v;
  try {
    const cn = v.$className;
    if (cn === "java.lang.String") return clip(v.toString());
    if (cn === undefined && typeof v.length === "number" &&
        (v.length === 0 || typeof v[0] === "number")) {
      const n = Math.min(v.length, CAP);
      const out: any = { hex: hexJS(v, n), len: v.length };
      const u = utf8JS(v, n);
      if (u !== null) out.utf8 = u;
      return out;
    }
    return { class: cn || "?", value: clip(String(v)) };
  } catch (e) { return { error: String(e) }; }
}

rpc.exports = {
  modules(filter?: string) {
    const needle = (filter ?? "").toLowerCase();
    return Process.enumerateModules()
      .filter(m => !needle || m.name.toLowerCase().includes(needle))
      .map(m => ({ name: m.name, base: m.base.toString(), size: m.size }));
  },
  exports(moduleName: string) {
    return Process.getModuleByName(moduleName).enumerateExports()
      .map(e => ({ name: e.name, address: e.address.toString() }));
  },
  javaEnumerate(filter: string) {
    // Case-insensitive substring match: the app's Java package (e.g.
    // sg.vp.owasp_mobile.OMTG_Android) is often cased differently from the
    // application id operators paste in from `/apps`
    // (sg.vp.owasp_mobile.omtg_android). A case-sensitive filter silently
    // returned 0 for the natural filter, so match case-insensitively.
    const needle = (filter ?? "").toLowerCase();
    const out: string[] = [];
    Java.perform(() => {
      Java.enumerateLoadedClassesSync()
        .filter(c => c.toLowerCase().includes(needle))
        .slice(0, 500)
        .forEach(c => out.push(c));
    });
    return out;
  },
  javaEnumerateMethods(cls: string) {
    const out: { name: string; signature: string }[] = [];
    Java.perform(() => {
      const klass = Java.use(cls);
      klass.class.getDeclaredMethods()
        .forEach((m: any) => out.push({ name: m.getName(), signature: m.toString() }));
    });
    return out;
  },
  javaHookInstall(cls: string, method: string, overload?: string[]) {
    let result: any = { hook: `${cls}.${method}`, since_seq: SEQ };
    Java.perform(() => {
      const klass: any = Java.use(cls);
      const m: any = klass[method];
      let target: any;
      if (overload && overload.length) {
        target = m.overload.apply(m, overload);
      } else if (m.overloads && m.overloads.length > 1) {
        result = { ambiguous: true,
          overloads: m.overloads.map((o: any) => o.argumentTypes.map((t: any) => t.className)) };
        return;
      } else {
        target = m;
      }
      const ov: string[] = (overload && overload.length)
        ? overload
        : (target.argumentTypes ? target.argumentTypes.map((t: any) => t.className) : []);
      target.implementation = function (...args: any[]) {
        const tid = Process.getCurrentThreadId();
        if (active.has(tid)) {                                   // re-entrancy guard
          send({ hook: true, seq: ++SEQ, class: cls, method, overload: ov, reentrant: true, thread: tid });
          return target.apply(this, args);
        }
        active.add(tid);
        const argsD = args.map(describe);
        let retD: any = null, threw = false;
        try {
          const r = target.apply(this, args);
          retD = describe(r);
          return r;
        } catch (e: any) {
          threw = true; retD = { error: String(e) };
          throw e;
        } finally {
          send({ hook: true, seq: ++SEQ, class: cls, method, overload: ov,
                 args: argsD, ret: retD, threw, thread: tid });
          active.delete(tid);
        }
      };
      result = { hook: `${cls}.${method}`, since_seq: SEQ };
    });
    return result;
  },
  javaHookRemove(cls: string, method: string, overload?: string[]) {
    Java.perform(() => {
      const klass: any = Java.use(cls);
      const m: any = klass[method];
      const target: any = (overload && overload.length) ? m.overload.apply(m, overload) : m;
      target.implementation = null;
    });
    return { removed: `${cls}.${method}` };
  },
  memRead(address: string, size: number) {
    return ptr(address).readByteArray(size);
  },
  memWrite(address: string, hexBytes: string) {
    const bytes = hexBytes.match(/.{1,2}/g)!.map(b => parseInt(b, 16));
    ptr(address).writeByteArray(bytes);
    return { written: bytes.length };
  },
};
