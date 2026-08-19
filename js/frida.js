import Java from 'frida-java-bridge';

/**
 * @typedef {{ name: string, value: string }} Field
 * @typedef {{ methods: Record<string, Field[]>, strings: Record<string, Field[]> }} Reflected
 * 
 * @typedef {{ v_addr: number, size: number }} TextSectionInfo
 * @typedef { Record<string, { text_info: TextSectionInfo, got_vaddrs: number[] }>} NativeFridaInfo
 * 
 * @typedef { Record<string, { decrypted: number[], relocations: { address: number, symbol: string }[] }> } NativeResults
 */


/** @param {Reflected} data */
function extractJava(data) {
  const lookups = { ...data.strings, ...data.methods };
  for (const [className, fields] of Object.entries(lookups)) {
    const JavaClass = Java.use(className);

    for (const field of fields) {
      const fieldRef = JavaClass[field.name];
      field.value = fieldRef.value.toString();
    }
  }

  return data;
}

/**
 * @param {NativeFridaInfo} info
 * @returns {NativeResults}
 */
function extractNative(info) {
  const /** @type {NativeResults} */ results = {}

  for (const [libName, data] of Object.entries(info)) {
    let module = getOrLoadModule(libName);

    const relocations = data.got_vaddrs.map(va => {
      const symbolPtr = module.base.add(ptr(va)).readPointer();
      const symbol = DebugSymbol.fromAddress(symbolPtr);

      return {
        address: va,
        symbol: symbol.name
      }
    });

    const dec = readLibMemory(module, data.text_info.v_addr, data.text_info.size);
    results[libName] = {
      decrypted: Array.from(dec),
      relocations
    };
  }

  return results;
}

/**
 * @param {Module} module
 * @param {number} offset
 * @param {number} length
 * @returns {Uint8Array}
 */
function readLibMemory(module, offset, length) {
  const targetAddr = module.base.add(offset);
  const arrBuf = targetAddr.readByteArray(length);
  return new Uint8Array(arrBuf);
}

/**
 * @param {string} libName
 */
function getOrLoadModule(libName) {
  let module = Process.findModuleByName(libName);
  if (module)
    return module;

  let shortName = libName.replace(/^lib/, '').replace(/\.so$/, '');

  Java.perform(() => {
    const ActivityThread = Java.use('android.app.ActivityThread');
    const context = ActivityThread.currentApplication().getApplicationContext();
    const classLoader = context.getClassLoader();
    const appClassName = context.getApplicationInfo().className.value;
    const AppClass = classLoader.loadClass(appClassName);
    const Runtime = Java.use('java.lang.Runtime');
    const runtime = Runtime.getRuntime();

    runtime.loadLibrary0(AppClass, shortName);
  });

  module = Process.getModuleByName(libName);
  return module;
}

rpc.exports = {
  extractJava: function (/** @type {Reflected} */ data) {
    return new Promise(function (resolve, reject) {
      Java.perform(function () {
        try {
          resolve(extractJava(data));
        } catch (e) {
          reject(e);
        }
      });
    });
  },
  extractNative: function (/** @type {NativeFridaInfo} */ info) {
    return new Promise(function (resolve, reject) {
      Java.perform(function () {
        try {
          resolve(extractNative(info));
        } catch (e) {
          reject(e);
        }
      });
    });
  }
};
