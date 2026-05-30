import Java from "frida-java-bridge";

rpc.exports = {
  modules(filter?: string) {
    return Process.enumerateModules()
      .filter(m => !filter || m.name.includes(filter))
      .map(m => ({ name: m.name, base: m.base.toString(), size: m.size }));
  },
  exports(moduleName: string) {
    return Process.getModuleByName(moduleName).enumerateExports()
      .map(e => ({ name: e.name, address: e.address.toString() }));
  },
  javaEnumerate(filter: string) {
    const out: string[] = [];
    Java.perform(() => {
      Java.enumerateLoadedClassesSync()
        .filter(c => c.includes(filter))
        .slice(0, 500)
        .forEach(c => out.push(c));
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
  memRead(address: string, size: number) {
    return ptr(address).readByteArray(size);
  },
  memWrite(address: string, hexBytes: string) {
    const bytes = hexBytes.match(/.{1,2}/g)!.map(b => parseInt(b, 16));
    ptr(address).writeByteArray(bytes);
    return { written: bytes.length };
  },
};
