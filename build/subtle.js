// Core
import { AlgorithmNames, Base64Url } from "webcrypto-core";
import * as core from "webcrypto-core";
import { PrepareAlgorithm, PrepareData } from "webcrypto-core";
// Base
import { nativeSubtle } from "./init";
import { Crypto } from "./crypto";
import { LinerError } from "./error";
import { string2buffer, buffer2string, Browser, BrowserInfo, assign, warn } from "./helper";
// Crypto
import { AesCrypto } from "./aes/crypto";
import { ShaCrypto } from "./sha/crypto";
// import { RsaCrypto } from "./rsa/crypto";
import { EcCrypto } from "./ec/crypto";
import { Pbkdf2Crypto } from './pbkdf2/crypto';
import { HmacCrypto } from './hmac/crypto';
import { HkdfCrypto } from './hkdf/crypto';
const keys = [];
function PrepareKey(key, subtle) {
    return Promise.resolve()
        .then(() => {
        if (!key.key) {
            if (!key.extractable) {
                throw new LinerError("'key' is Native CryptoKey. It can't be converted to JS CryptoKey");
            }
            else {
                const crypto = new Crypto();
                return crypto.subtle.exportKey("jwk", key)
                    .then((jwk) => {
                    let alg = GetHashAlgorithm(key);
                    if (alg) {
                        alg = assign(alg, key.algorithm);
                    }
                    return subtle.importKey("jwk", jwk, alg, true, key.usages);
                });
            }
        }
        else {
            return key;
        }
    });
}
export class SubtleCrypto extends core.SubtleCrypto {
    generateKey(algorithm, extractable, keyUsages) {
        const args = arguments;
        let alg;
        return super.generateKey.apply(this, args)
            .then((d) => {
            alg = PrepareAlgorithm(algorithm);
            const browser = BrowserInfo();
            if ((browser.name === Browser.Edge && alg.name.toUpperCase() === AlgorithmNames.AesGCM) ||
                // Don't do AES-GCM key generation, because Edge throws errors on GCM encrypt, decrypt, wrapKey, unwrapKey
                CheckAppleRsaOAEP(alg.name)) {
                return;
            }
            if (nativeSubtle) {
                try {
                    return nativeSubtle.generateKey.apply(nativeSubtle, args)
                        .catch((e) => {
                        warn(`WebCrypto: native generateKey for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    warn(`WebCrypto: native generateKey for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                }
            }
        })
            .then((generatedKeys) => {
            if (generatedKeys) {
                let promise = Promise.resolve(generatedKeys);
                /**
                 * Safari issue
                 * https://github.com/PeculiarVentures/webcrypto-liner/issues/39
                 * if public key cannot be exported in correct JWK format, then run new generateKey
                 */
                if (BrowserInfo().name === Browser.Safari &&
                    (alg.name.toUpperCase() === AlgorithmNames.EcDH.toUpperCase() ||
                        alg.name.toUpperCase() === AlgorithmNames.EcDSA.toUpperCase())) {
                    const pubKey = generatedKeys.publicKey;
                    promise = promise.then(() => {
                        return this.exportKey("jwk", pubKey)
                            .then((jwk) => {
                            return this.exportKey("spki", pubKey)
                                .then((spki) => {
                                const x = Base64Url.decode(jwk.x);
                                const y = Base64Url.decode(jwk.y);
                                const len = x.length + y.length;
                                const spkiBuf = new Uint8Array(spki);
                                for (let i = 0; i < len; i++) {
                                    const spkiByte = spkiBuf[spkiBuf.length - i - 1];
                                    let pointByte;
                                    if (i < y.length) {
                                        pointByte = y[y.length - i - 1];
                                    }
                                    else {
                                        pointByte = x[x.length + y.length - i - 1];
                                    }
                                    if (spkiByte !== pointByte) {
                                        // regenerate new key
                                        warn("WebCrypto: EC key has wrong public key JWK. Key pair will be recreated");
                                        return this.generateKey(algorithm, extractable, keyUsages);
                                    }
                                }
                                return generatedKeys;
                            });
                        });
                    });
                }
                return promise.then((keys2) => {
                    FixCryptoKeyUsages(keys2, keyUsages);
                    SetHashAlgorithm(alg, keys2);
                    return keys2;
                });
            }
            let Class;
            switch (alg.name.toLowerCase()) {
                case AlgorithmNames.AesECB.toLowerCase():
                case AlgorithmNames.AesCBC.toLowerCase():
                case AlgorithmNames.AesGCM.toLowerCase():
                    Class = AesCrypto;
                    break;
                case AlgorithmNames.EcDSA.toLowerCase():
                case AlgorithmNames.EcDH.toLowerCase():
                    Class = EcCrypto;
                    break;
                // case AlgorithmNames.RsaOAEP.toLowerCase():
                // case AlgorithmNames.RsaPSS.toLowerCase():
                // case AlgorithmNames.RsaSSA.toLowerCase():
                //     Class = RsaCrypto;
                //     break;
                default:
                    throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, alg.name.toLowerCase());
            }
            return Class.generateKey(alg, extractable, keyUsages);
        });
    }
    digest(algorithm, data) {
        const args = arguments;
        let alg;
        let dataBytes;
        return super.digest.apply(this, args)
            .then((d) => {
            alg = PrepareAlgorithm(algorithm);
            dataBytes = PrepareData(data, "data");
            if (nativeSubtle) {
                try {
                    return nativeSubtle.digest.apply(nativeSubtle, args)
                        .catch((e) => {
                        warn(`WebCrypto: native digest for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    warn(`WebCrypto: native digest for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                }
            }
        })
            .then((digest) => {
            if (digest) {
                return digest;
            }
            return ShaCrypto.digest(alg, dataBytes);
        });
    }
    sign(algorithm, key, data) {
        const args = arguments;
        let alg;
        let dataBytes;
        return super.sign.apply(this, args)
            .then((d) => {
            alg = PrepareAlgorithm(algorithm);
            dataBytes = PrepareData(data, "data");
            const alg2 = GetHashAlgorithm(key);
            if (alg2) {
                args[0] = assign(alg, alg2);
            }
            if (nativeSubtle) {
                try {
                    return nativeSubtle.sign.apply(nativeSubtle, args)
                        .catch((e) => {
                        warn(`WebCrypto: native sign for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    warn(`WebCrypto: native sign for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                }
            }
        })
            .then((signature) => {
            if (signature) {
                return signature;
            }
            let Class;
            switch (alg.name.toLowerCase()) {
                case AlgorithmNames.EcDSA.toLowerCase():
                    Class = EcCrypto;
                    break;
                // case AlgorithmNames.RsaSSA.toLowerCase():
                // case AlgorithmNames.RsaPSS.toLowerCase():
                //     Class = RsaCrypto;
                //     break;
                case AlgorithmNames.Hmac.toLowerCase():
                    //return HmacCrypto.sign(alg, key, dataBytes);
                    Class = HmacCrypto;
                    break;
                default:
                    throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, alg.name.toLowerCase());
            }
            return PrepareKey(key, Class)
                .then((preparedKey) => Class.sign(alg, preparedKey, dataBytes));
        });
    }
    verify(algorithm, key, signature, data) {
        const args = arguments;
        let alg;
        let signatureBytes;
        let dataBytes;
        return super.verify.apply(this, args)
            .then((d) => {
            alg = PrepareAlgorithm(algorithm);
            signatureBytes = PrepareData(signature, "data");
            dataBytes = PrepareData(data, "data");
            const alg2 = GetHashAlgorithm(key);
            if (alg2) {
                args[0] = assign(alg, alg2);
            }
            if (nativeSubtle) {
                try {
                    return nativeSubtle.verify.apply(nativeSubtle, args)
                        .catch((e) => {
                        warn(`WebCrypto: native verify for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    warn(`WebCrypto: native verify for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                }
            }
        })
            .then((result) => {
            if (typeof result === "boolean") {
                return result;
            }
            let Class;
            switch (alg.name.toLowerCase()) {
                case AlgorithmNames.EcDSA.toLowerCase():
                    Class = EcCrypto;
                    break;
                // case AlgorithmNames.RsaSSA.toLowerCase():
                // case AlgorithmNames.RsaPSS.toLowerCase():
                //     Class = RsaCrypto;
                //     break;
                default:
                    throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, alg.name.toLowerCase());
            }
            // return PrepareKey(key, Class)
            //     .then((preparedKey) => Class.verify(alg, preparedKey, signatureBytes, dataBytes));
        });
    }
    deriveBits(algorithm, baseKey, length) {
        const args = arguments;
        let alg;
        return super.deriveBits.apply(this, args)
            .then((bits) => {
            alg = PrepareAlgorithm(algorithm);
            if (nativeSubtle) {
                try {
                    return nativeSubtle.deriveBits.apply(nativeSubtle, args)
                        .catch((e) => {
                        warn(`WebCrypto: native deriveBits for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    // Edge throws error. Don't know Why.
                    warn(`WebCrypto: native deriveBits for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                }
            }
        })
            .then((bits) => {
            if (bits) {
                return bits;
            }
            let Class;
            switch (alg.name.toLowerCase()) {
                case AlgorithmNames.EcDH.toLowerCase():
                    Class = EcCrypto;
                    break;
                case AlgorithmNames.Pbkdf2.toLowerCase():
                    Class = Pbkdf2Crypto;
                    break;
                case AlgorithmNames.Hkdf.toLowerCase():
                    Class = HkdfCrypto;
                    break;
                default:
                    throw new LinerError(LinerError.NOT_SUPPORTED, "deriveBits");
            }
            return Class.deriveBits(alg, baseKey, length);
        });
    }
    deriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
        const args = arguments;
        let alg;
        let algDerivedKey;
        return super.deriveKey.apply(this, args)
            .then((bits) => {
            alg = PrepareAlgorithm(algorithm);
            algDerivedKey = PrepareAlgorithm(derivedKeyType);
            if (nativeSubtle) {
                try {
                    return nativeSubtle.deriveKey.apply(nativeSubtle, args)
                        .catch((e) => {
                        warn(`WebCrypto: native deriveKey for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    // Edge doesn't go to catch of Promise
                    warn(`WebCrypto: native deriveKey for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                }
            }
        })
            .then((key) => {
            if (key) {
                FixCryptoKeyUsages(key, keyUsages);
                return key;
            }
            let Class;
            switch (alg.name.toLowerCase()) {
                case AlgorithmNames.EcDH.toLowerCase():
                    Class = EcCrypto;
                    break;
                case AlgorithmNames.Pbkdf2.toLowerCase():
                    Class = Pbkdf2Crypto;
                    break;
                case AlgorithmNames.Hkdf.toLowerCase():
                    Class = HkdfCrypto;
                    break;
                default:
                    throw new LinerError(LinerError.NOT_SUPPORTED, "deriveKey");
            }
            return Class.deriveKey(alg, baseKey, algDerivedKey, extractable, keyUsages);
        });
    }
    encrypt(algorithm, key, data) {
        const args = arguments;
        let alg;
        let dataBytes;
        return super.encrypt.apply(this, args)
            .then((bits) => {
            alg = PrepareAlgorithm(algorithm);
            dataBytes = PrepareData(data, "data");
            if (nativeSubtle) {
                try {
                    return nativeSubtle.encrypt.apply(nativeSubtle, args)
                        .catch((e) => {
                        warn(`WebCrypto: native 'encrypt' for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    warn(`WebCrypto: native 'encrypt' for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                }
            }
        })
            .then((msg) => {
            if (msg) {
                if (BrowserInfo().name === Browser.IE &&
                    alg.name.toUpperCase() === AlgorithmNames.AesGCM &&
                    msg.ciphertext) {
                    // Concatenate values in IE
                    const buf = new Uint8Array(msg.ciphertext.byteLength + msg.tag.byteLength);
                    let count = 0;
                    new Uint8Array(msg.ciphertext).forEach((v) => buf[count++] = v);
                    new Uint8Array(msg.tag).forEach((v) => buf[count++] = v);
                    msg = buf.buffer;
                }
                return Promise.resolve(msg);
            }
            let Class;
            switch (alg.name.toLowerCase()) {
                case AlgorithmNames.AesECB.toLowerCase():
                case AlgorithmNames.AesCBC.toLowerCase():
                case AlgorithmNames.AesGCM.toLowerCase():
                    Class = AesCrypto;
                    break;
                // case AlgorithmNames.RsaOAEP.toLowerCase():
                //     Class = RsaCrypto;
                //     break;
                default:
                    throw new LinerError(LinerError.NOT_SUPPORTED, "encrypt");
            }
            return PrepareKey(key, Class)
                .then((preparedKey) => Class.encrypt(alg, preparedKey, dataBytes));
        });
    }
    decrypt(algorithm, key, data) {
        const args = arguments;
        let alg;
        let dataBytes;
        return super.decrypt.apply(this, args)
            .then((bits) => {
            alg = PrepareAlgorithm(algorithm);
            dataBytes = PrepareData(data, "data");
            let dataBytes2 = dataBytes;
            if (BrowserInfo().name === Browser.IE &&
                alg.name.toUpperCase() === AlgorithmNames.AesGCM) {
                // Split buffer
                const len = dataBytes.byteLength - (alg.tagLength / 8);
                dataBytes2 = {
                    ciphertext: dataBytes.buffer.slice(0, len),
                    tag: dataBytes.buffer.slice(len, dataBytes.byteLength),
                };
            }
            if (!key.key) {
                return nativeSubtle.decrypt.call(nativeSubtle, alg, key, dataBytes2);
            }
            else {
                let Class;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.AesECB.toLowerCase():
                    case AlgorithmNames.AesCBC.toLowerCase():
                    case AlgorithmNames.AesGCM.toLowerCase():
                        Class = AesCrypto;
                        break;
                    // case AlgorithmNames.RsaOAEP.toLowerCase():
                    //     Class = RsaCrypto;
                    //     break;
                    default:
                        throw new LinerError(LinerError.NOT_SUPPORTED, "decrypt");
                }
                return Class.decrypt(alg, key, dataBytes);
            }
        });
    }
    wrapKey(format, key, wrappingKey, wrapAlgorithm) {
        const args = arguments;
        let alg;
        return super.wrapKey.apply(this, args)
            .then((bits) => {
            alg = PrepareAlgorithm(wrapAlgorithm);
            if (nativeSubtle) {
                try {
                    return nativeSubtle.wrapKey.apply(nativeSubtle, args)
                        .catch((e) => {
                        warn(`WebCrypto: native 'wrapKey' for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    warn(`WebCrypto: native 'wrapKey' for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                }
            }
        })
            .then((msg) => {
            if (msg) {
                return msg;
            }
            let Class;
            switch (alg.name.toLowerCase()) {
                case AlgorithmNames.AesECB.toLowerCase():
                case AlgorithmNames.AesCBC.toLowerCase():
                case AlgorithmNames.AesGCM.toLowerCase():
                    Class = AesCrypto;
                    break;
                // case AlgorithmNames.RsaOAEP.toLowerCase():
                //     Class = RsaCrypto;
                //     break;
                default:
                    throw new LinerError(LinerError.NOT_SUPPORTED, "wrapKey");
            }
            return Class.wrapKey(format, key, wrappingKey, alg);
        });
    }
    unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
        const args = arguments;
        let alg;
        let algKey;
        let dataBytes;
        return super.unwrapKey.apply(this, args)
            .then((bits) => {
            alg = PrepareAlgorithm(unwrapAlgorithm);
            algKey = PrepareAlgorithm(unwrappedKeyAlgorithm);
            dataBytes = PrepareData(wrappedKey, "wrappedKey");
            if (!unwrappingKey.key) {
                return nativeSubtle.unwrapKey.apply(nativeSubtle, args)
                    .catch((err) => {
                    // Edge throws errors on unwrapKey native functions
                    // Use custom unwrap function
                    return this.decrypt(alg, unwrappingKey, wrappedKey)
                        .then((decryptedData) => {
                        let preparedData;
                        if (format === "jwk") {
                            preparedData = JSON.parse(buffer2string(new Uint8Array(decryptedData)));
                        }
                        else {
                            preparedData = decryptedData;
                        }
                        return this.importKey(format, preparedData, algKey, extractable, keyUsages);
                    });
                })
                    .then((k) => {
                    if (k) {
                        FixCryptoKeyUsages(k, keyUsages);
                        return k;
                    }
                })
                    .catch((error) => {
                    console.error(error);
                    throw new Error("Cannot unwrap key from incoming data");
                });
            }
            else {
                let Class;
                switch (alg.name.toLowerCase()) {
                    case AlgorithmNames.AesECB.toLowerCase():
                    case AlgorithmNames.AesCBC.toLowerCase():
                    case AlgorithmNames.AesGCM.toLowerCase():
                        Class = AesCrypto;
                        break;
                    // case AlgorithmNames.RsaOAEP.toLowerCase():
                    //     Class = RsaCrypto;
                    //     break;
                    default:
                        throw new LinerError(LinerError.NOT_SUPPORTED, "unwrapKey");
                }
                return Class.unwrapKey(format, dataBytes, unwrappingKey, alg, algKey, extractable, keyUsages);
            }
        });
    }
    exportKey(format, key) {
        const args = arguments;
        return super.exportKey.apply(this, args)
            .then(() => {
            if (nativeSubtle) {
                try {
                    return nativeSubtle.exportKey.apply(nativeSubtle, args)
                        .catch((e) => {
                        warn(`WebCrypto: native 'exportKey' for ${key.algorithm.name} doesn't work.`, e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    warn(`WebCrypto: native 'exportKey' for ${key.algorithm.name} doesn't work.`, e && e.message || "Unknown message");
                }
            }
        })
            .then((msg) => {
            if (msg) {
                if (format === "jwk" && msg instanceof ArrayBuffer) {
                    msg = buffer2string(new Uint8Array(msg));
                    msg = JSON.parse(msg);
                }
                let alg = GetHashAlgorithm(key);
                if (!alg) {
                    alg = assign({}, key.algorithm);
                }
                FixExportJwk(msg, alg, key.usages);
                return Promise.resolve(msg);
            }
            if (!key.key) {
                throw new LinerError("Cannot export native CryptoKey from JS implementation");
            }
            let Class;
            switch (key.algorithm.name.toLowerCase()) {
                case AlgorithmNames.AesECB.toLowerCase():
                case AlgorithmNames.AesCBC.toLowerCase():
                case AlgorithmNames.AesGCM.toLowerCase():
                    Class = AesCrypto;
                    break;
                case AlgorithmNames.EcDH.toLowerCase():
                case AlgorithmNames.EcDSA.toLowerCase():
                    Class = EcCrypto;
                    break;
                // case AlgorithmNames.RsaSSA.toLowerCase():
                // case AlgorithmNames.RsaPSS.toLowerCase():
                // case AlgorithmNames.RsaOAEP.toLowerCase():
                //     Class = RsaCrypto;
                //     break;
                case AlgorithmNames.Hmac.toLowerCase():
                    Class = HmacCrypto;
                    break;
                default:
                    throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name.toLowerCase());
            }
            return Class.exportKey(format, key);
        });
    }
    importKey(format, keyData, algorithm, extractable, keyUsages) {
        const args = arguments;
        let alg;
        let dataAny;
        return super.importKey.apply(this, args)
            .then((bits) => {
            alg = PrepareAlgorithm(algorithm);
            dataAny = keyData;
            // Fix: Safari
            const browser = BrowserInfo();
            if (format === "jwk" && ((browser.name === Browser.Safari && !/^11/.test(browser.version)) ||
                browser.name === Browser.IE)) {
                // Converts JWK to ArrayBuffer
                if (BrowserInfo().name === Browser.IE) {
                    keyData = assign({}, keyData);
                    FixImportJwk(keyData);
                }
                args[1] = string2buffer(JSON.stringify(keyData)).buffer;
            }
            // End: Fix
            if (ArrayBuffer.isView(keyData)) {
                dataAny = PrepareData(keyData, "keyData");
            }
            if (CheckAppleRsaOAEP(alg.name)) {
                // Don't use native importKey for RSA-OAEP on Safari before v11
                // https://github.com/PeculiarVentures/webcrypto-liner/issues/53
                return;
            }
            if (nativeSubtle) {
                try {
                    return nativeSubtle.importKey.apply(nativeSubtle, args)
                        .catch((e) => {
                        warn(`WebCrypto: native 'importKey' for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                    });
                }
                catch (e) {
                    warn(`WebCrypto: native 'importKey' for ${alg.name} doesn't work.`, e && e.message || "Unknown message");
                }
            }
        })
            .then((k) => {
            if (k) {
                SetHashAlgorithm(alg, k);
                FixCryptoKeyUsages(k, keyUsages);
                return Promise.resolve(k);
            }
            let Class;
            switch (alg.name.toLowerCase()) {
                case AlgorithmNames.AesECB.toLowerCase():
                case AlgorithmNames.AesCBC.toLowerCase():
                case AlgorithmNames.AesGCM.toLowerCase():
                    Class = AesCrypto;
                    break;
                case AlgorithmNames.EcDH.toLowerCase():
                case AlgorithmNames.EcDSA.toLowerCase():
                    Class = EcCrypto;
                    break;
                // case AlgorithmNames.RsaSSA.toLowerCase():
                // case AlgorithmNames.RsaPSS.toLowerCase():
                // case AlgorithmNames.RsaOAEP.toLowerCase():
                //     Class = RsaCrypto;
                //     break;
                case AlgorithmNames.Pbkdf2.toLowerCase():
                    Class = Pbkdf2Crypto;
                    break;
                case AlgorithmNames.Hmac.toLowerCase():
                    Class = HmacCrypto;
                    break;
                case AlgorithmNames.Hkdf.toLowerCase():
                    Class = HkdfCrypto;
                    break;
                default:
                    throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, alg.name.toLowerCase());
            }
            return Class.importKey(format, dataAny, alg, extractable, keyUsages);
        });
    }
}
// save hash alg for RSA keys
function SetHashAlgorithm(alg, key) {
    if ((BrowserInfo().name === Browser.IE || BrowserInfo().name === Browser.Edge || BrowserInfo().name === Browser.Safari) && /^rsa/i.test(alg.name)) {
        if (key.privateKey) {
            keys.push({ hash: alg.hash, key: key.privateKey });
            keys.push({ hash: alg.hash, key: key.publicKey });
        }
        else {
            keys.push({ hash: alg.hash, key: key });
        }
    }
}
// fix hash alg for rsa key
function GetHashAlgorithm(key) {
    let alg = null;
    keys.some((item) => {
        if (item.key === key) {
            alg = assign({}, key.algorithm, { hash: item.hash });
            return true;
        }
        return false;
    });
    return alg;
}
// Extend Uint8Array for IE
if (!Uint8Array.prototype.forEach) {
    // tslint:disable-next-line:only-arrow-functions
    // tslint:disable-next-line:space-before-function-paren
    Uint8Array.prototype.forEach = function (cb) {
        for (let i = 0; i < this.length; i++) {
            cb(this[i], i, this);
        }
    };
}
if (!Uint8Array.prototype.slice) {
    // tslint:disable-next-line:only-arrow-functions
    // tslint:disable-next-line:space-before-function-paren
    Uint8Array.prototype.slice = function (start, end) {
        return new Uint8Array(this.buffer.slice(start, end));
    };
}
if (!Uint8Array.prototype.filter) {
    // tslint:disable-next-line:only-arrow-functions
    // tslint:disable-next-line:space-before-function-paren
    Uint8Array.prototype.filter = function (cb) {
        const buf = [];
        for (let i = 0; i < this.length; i++) {
            if (cb(this[i], i, this)) {
                buf.push(this[i]);
            }
        }
        return new Uint8Array(buf);
    };
}
function FixCryptoKeyUsages(key, keyUsages) {
    const keyArray = [];
    if (key.privateKey) {
        keyArray.push(key.privateKey);
        keyArray.push(key.publicKey);
    }
    else {
        keyArray.push(key);
    }
    keyArray.forEach((k) => {
        if ("keyUsage" in k) {
            k.usages = k.keyUsage || [];
            // add usages
            if (!k.usages.length) {
                ["verify", "encrypt", "wrapKey"]
                    .forEach((usage) => {
                    if (keyUsages.indexOf(usage) > -1 && (k.type === "public" || k.type === "secret")) {
                        k.usages.push(usage);
                    }
                });
                ["sign", "decrypt", "unwrapKey", "deriveKey", "deriveBits"]
                    .forEach((usage) => {
                    if (keyUsages.indexOf(usage) > -1 && (k.type === "private" || k.type === "secret")) {
                        k.usages.push(usage);
                    }
                });
            }
        }
    });
}
function FixExportJwk(jwk, alg, keyUsages) {
    if (alg && BrowserInfo().name === Browser.IE) {
        // ext
        if ("extractable" in jwk) {
            jwk.ext = jwk.extractable;
            delete jwk.extractable;
        }
        // add alg
        let CryptoClass = null;
        switch (alg.name.toUpperCase()) {
            // case AlgorithmNames.RsaOAEP.toUpperCase():
            // case AlgorithmNames.RsaPSS.toUpperCase():
            // case AlgorithmNames.RsaSSA.toUpperCase():
            //     CryptoClass = RsaCrypto;
            //     break;
            case AlgorithmNames.AesECB.toUpperCase():
            case AlgorithmNames.AesCBC.toUpperCase():
            case AlgorithmNames.AesGCM.toUpperCase():
                CryptoClass = AesCrypto;
                break;
            default:
                throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, alg.name.toUpperCase());
        }
        if (CryptoClass && !jwk.alg) {
            jwk.alg = CryptoClass.alg2jwk(alg);
        }
        // add key_ops
        if (!("key_ops" in jwk)) {
            jwk.key_ops = keyUsages;
        }
    }
}
function FixImportJwk(jwk) {
    if (BrowserInfo().name === Browser.IE) {
        // ext
        if ("ext" in jwk) {
            jwk.extractable = jwk.ext;
            delete jwk.ext;
        }
        delete jwk.key_ops;
        delete jwk.alg;
    }
}
function CheckAppleRsaOAEP(algName) {
    const version = /AppleWebKit\/(\d+)/.exec(self.navigator.userAgent);
    return (algName.toUpperCase() === AlgorithmNames.RsaOAEP && version && parseInt(version[1], 10) < 604);
}
