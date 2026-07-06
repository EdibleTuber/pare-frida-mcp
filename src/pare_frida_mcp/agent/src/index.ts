import Java from "frida-java-bridge";

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
  javaHookInstall(cls: string, method: string, overload?: string) {
    Java.perform(() => {
      const klass = Java.use(cls);
      const target = overload ? klass[method].overload(overload) : klass[method];
      target.implementation = function (...args: any[]) {
        send({ type: "send", source: `${cls}.${method}`,
               payload: { class: cls, method, args: args.map(String) } });
        return target.apply(this, args);
      };
    });
    return { hook: `${cls}.${method}` };
  },
  javaHookRemove(cls: string, method: string, overload?: string) {
    Java.perform(() => {
      const klass = Java.use(cls);
      const target = overload ? klass[method].overload(overload) : klass[method];
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
