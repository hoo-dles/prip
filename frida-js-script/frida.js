import Java from 'frida-java-bridge';

/**
 * @typedef {{ name: string, value: string }} Field
 * @typedef {{ methods: Record<string, Field[]>, strings: Record<string, Field[]> }} Reflected
 * 
 * @typedef {{ v_addr: number, size: number }} TextSectionInfo
 * @typedef { Record<string, { text_info: TextSectionInfo, got_vaddrs: number[] }>} NativeFridaInfo
 * 
 * @typedef {{ module_path: string, offset: number }} MissingSymbol
 * @typedef {{ address: number, symbol: string, missing?: MissingSymbol}} Relocation
 * 
 * @typedef { Record<string, { decrypted: number[], relocations: Relocation[] }> } NativeResults
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

class SymbolLookupError extends Error {
    /**
       * @param {Module} module
       * @param {NativePointer} offset
       */
    constructor(module, offset) {
        super("Cannot find symbol name");

        this.name = "SymbolLookupError";
        this.module = module;
        this.offset = offset;
    }
}

/**
 * @param {NativeFridaInfo} info
 * @returns {NativeResults}
 */
function extractNative(info) {
    const /** @type {NativeResults} */ results = {}

    for (const [libName, data] of Object.entries(info)) {
        let module = getOrLoadModule(libName);

        const relocations = [];
        for (const va of data.got_vaddrs) {
            const symbolPtr = module.base.add(ptr(va)).readPointer();

            try {
                const symbol = getPublicExportFromAddress(symbolPtr)
                relocations.push({
                    address: va,
                    symbol: symbol
                });
            } catch (error) {
                if (error instanceof SymbolLookupError) {
                    relocations.push({
                        address: va,
                        symbol: "",
                        missing: {
                            module_path: error.module.path,
                            offset: error.offset.toUInt32()
                        }
                    });
                } else throw error;
            }
        }

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

/**
 * @param {NativePointer} targetPtr
 */
function getSafeSymbol(targetPtr) {
    var mod = Process.findModuleByAddress(targetPtr);
    if (!mod) {
        throw new Error(`Cannot find module for symbol pointer`)
    }

    var exports = mod.enumerateExports();
    for (var i = 0; i < exports.length; i++) {
        if (exports[i].address.equals(targetPtr)) {
            return {
                module: mod,
                name: exports[i].name,
                address: exports[i].address
            }
        }
    }

    var offset = targetPtr.sub(mod.base);
    throw new SymbolLookupError(mod, offset);
}

const ARCH_TAGS = [
    'aarch64', 'arm', 'neon', 'mte', 'v8',
    'sve2?', 'pac', 'opt', 'shared', 'static'
].join('|');

// internal prefixes
const PREFIX_REGEX = /^(portable_simd_|__kernel_|__libc_|__)/;
// architecture, optimization, and SIMD suffixes
const ARCH_REGEX = new RegExp(`_(${ARCH_TAGS}).*$`);
// locale (_l) tags
const TRAILING_LOCALE_REGEX = /_l$/;

/**
 * Resolves a memory address to its public exported symbol name and module.
 * 
 * @param {NativePointer} targetPtr
 * @returns {string}
 */
function getPublicExportFromAddress(targetPtr) {
    const symbol = getSafeSymbol(targetPtr);

    const candidates = new Set();
    const cleanedName = symbol.name
        .replace(PREFIX_REGEX, '')
        .replace(ARCH_REGEX, '')
        .replace(TRAILING_LOCALE_REGEX, '');

    // Check cleaned name FIRST (some locale/reentrant variants are available on newer versions of
    // Android, but not all supported versions)
    candidates.add(cleanedName);
    candidates.add(symbol.name);

    for (const candidate of candidates) {
        const resolvedAddr = symbol.module.findExportByName(candidate);
        if (resolvedAddr && resolvedAddr.equals(symbol.address))
            return candidate;
    }
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
