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
    if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return null;
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
  javaHookInstall(cls: string, method: string, overload?: any[]) {
    let result: any = { hook: `${cls}.${method}`, since_seq: SEQ };
    Java.perform(() => {
      const klass: any = Java.use(cls);
      const m: any = klass[method];

      const argTypesOf = (t: any): string[] =>
        (t.argumentTypes ? t.argumentTypes.map((x: any) => x.className) : []);

      // Install the observing hook (decoded args + return) on one resolved overload.
      const installOn = (target: any, ov: string[]) => {
        target.implementation = function (...args: any[]) {
          const tid = Process.getCurrentThreadId();
          // Re-entrancy guard is held ONLY while decoding, so describe() can never
          // recurse into a hooked method. It is deliberately NOT held across
          // target.apply: a hooked callee invoked by a hooked caller on the same
          // thread must still be captured normally, not suppressed to a reentrant
          // event (e.g. hooking both encryptString and the CipherOutputStream.write
          // it calls).
          if (active.has(tid)) {
            send({ hook: true, seq: ++SEQ, class: cls, method, overload: ov, reentrant: true, thread: tid });
            return target.apply(this, args);
          }
          active.add(tid);
          let argsD: any;
          try { argsD = args.map(describe); } finally { active.delete(tid); }
          let retD: any = null, threw = false;
          try {
            const r = target.apply(this, args);          // original runs with the guard released
            active.add(tid);
            try { retD = describe(r); } finally { active.delete(tid); }
            return r;
          } catch (e: any) {
            threw = true; retD = { error: String(e) };
            throw e;
          } finally {
            send({ hook: true, seq: ++SEQ, class: cls, method, overload: ov,
                   args: argsD, ret: retD, threw, thread: tid });
          }
        };
      };

      // Hook EVERY overload of the method; return each one's descriptor list.
      const hookAll = (): string[][] => {
        const all = (m.overloads && m.overloads.length) ? m.overloads : [m];
        const hooked: string[][] = [];
        for (const t of all) { const ov = argTypesOf(t); installOn(t, ov); hooked.push(ov); }
        return hooked;
      };

      if (overload && overload.length) {
        // Try the caller's overload as given (frida wants descriptor strings, e.g.
        // "[B"). If it does not resolve — callers, especially LLMs, often pass a
        // non-descriptor shape — do NOT fail silently: hook every overload so a
        // correct target still fires, and report the valid descriptors so the
        // caller can refine. Shape-agnostic: handles any unresolvable input.
        try {
          const target = m.overload.apply(m, overload);
          const ov = argTypesOf(target);
          installOn(target, ov);
          result = { hook: `${cls}.${method}`, overload: ov, since_seq: SEQ };
        } catch (e: any) {
          const hooked = hookAll();
          result = { hook: `${cls}.${method}`, since_seq: SEQ,
            note: `overload ${JSON.stringify(overload)} did not resolve; hooked all `
                  + `${hooked.length} overload(s) instead`,
            overloads: hooked };
        }
        return;
      }

      if (m.overloads && m.overloads.length > 1) {
        result = { ambiguous: true,
          overloads: m.overloads.map((o: any) => o.argumentTypes.map((t: any) => t.className)) };
        return;
      }

      const target = (m.overloads && m.overloads.length) ? m.overloads[0] : m;
      installOn(target, argTypesOf(target));
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
