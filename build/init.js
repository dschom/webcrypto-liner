import { LinerError } from "./error";
let w;
if (typeof self === "undefined") {
    throw new Error("this module can't be used from node");
}
else {
    w = self;
}
export const nativeCrypto = w.msCrypto || w.crypto || {};
export let nativeSubtle = null;
try {
    nativeSubtle = nativeCrypto.subtle || nativeCrypto.webkitSubtle;
}
catch (err) {
    // Safari throws error on crypto.webkitSubtle in Worker
}
function WrapFunction(subtle, name) {
    const fn = subtle[name];
    // tslint:disable-next-line:only-arrow-functions
    subtle[name] = function () {
        const args = arguments;
        return new Promise((resolve, reject) => {
            const op = fn.apply(subtle, args);
            op.oncomplete = (e) => {
                resolve(e.target.result);
            };
            op.onerror = (e) => {
                reject(`Error on running '${name}' function`);
            };
        });
    };
}
if (w.msCrypto) {
    if (!w.Promise) {
        throw new LinerError(LinerError.MODULE_NOT_FOUND, "Promise", "https://www.promisejs.org");
    }
    WrapFunction(nativeSubtle, "generateKey");
    WrapFunction(nativeSubtle, "digest");
    WrapFunction(nativeSubtle, "sign");
    WrapFunction(nativeSubtle, "verify");
    WrapFunction(nativeSubtle, "encrypt");
    WrapFunction(nativeSubtle, "decrypt");
    WrapFunction(nativeSubtle, "importKey");
    WrapFunction(nativeSubtle, "exportKey");
    WrapFunction(nativeSubtle, "wrapKey");
    WrapFunction(nativeSubtle, "unwrapKey");
    WrapFunction(nativeSubtle, "deriveKey");
    WrapFunction(nativeSubtle, "deriveBits");
}
// fix: Math.imul for IE
if (!Math.imul) {
    // tslint:disable-next-line:only-arrow-functions
    Math.imul = function imul(a, b) {
        const ah = (a >>> 16) & 0xffff;
        const al = a & 0xffff;
        const bh = (b >>> 16) & 0xffff;
        const bl = b & 0xffff;
        return ((al * bl) + (((ah * bl + al * bh) << 16) >>> 0) | 0);
    };
}
