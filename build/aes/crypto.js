import { BaseCrypto, AlgorithmNames, AlgorithmError, Base64Url, PrepareData } from "webcrypto-core";
import { LinerError } from "../error";
import { CryptoKey } from "../key";
import { string2buffer, buffer2string } from "../helper";
import { nativeCrypto } from "../init";
export class AesCrypto extends BaseCrypto {
    static generateKey(algorithm, extractable, usages) {
        return Promise.resolve()
            .then(() => {
            this.checkModule();
            // gat random bytes for key
            const key = nativeCrypto.getRandomValues(new Uint8Array(algorithm.length / 8));
            // set key params
            const aesKey = new CryptoKey({
                type: "secret",
                algorithm,
                extractable,
                usages,
            });
            aesKey.key = key;
            return aesKey;
        });
    }
    static encrypt(algorithm, key, data) {
        return Promise.resolve()
            .then(() => {
            let res;
            switch (algorithm.name.toUpperCase()) {
                case AlgorithmNames.AesECB:
                    const algECB = algorithm;
                    ;
                    res = asmCrypto.AES_ECB.encrypt(data, key.key, !!algECB.padding);
                    break;
                case AlgorithmNames.AesCBC:
                    const algCBC = algorithm;
                    res = asmCrypto.AES_CBC.encrypt(data, key.key, undefined, PrepareData(algCBC.iv, "iv"));
                    break;
                case AlgorithmNames.AesGCM:
                    const algGCM = algorithm;
                    algGCM.tagLength = algGCM.tagLength || 128;
                    let additionalData;
                    if (algGCM.additionalData) {
                        additionalData = PrepareData(algGCM.additionalData, "additionalData");
                    }
                    res = asmCrypto.AES_GCM.encrypt(data, key.key, algGCM.iv, additionalData, algGCM.tagLength / 8);
                    break;
                default:
                    throw new LinerError(AlgorithmError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
            return res.buffer;
        });
    }
    static decrypt(algorithm, key, data) {
        return Promise.resolve()
            .then(() => {
            let res;
            switch (algorithm.name.toUpperCase()) {
                case AlgorithmNames.AesECB:
                    const algECB = algorithm;
                    res = asmCrypto.AES_ECB.decrypt(data, key.key, !!algECB.padding);
                    break;
                case AlgorithmNames.AesCBC:
                    const algCBC = algorithm;
                    res = asmCrypto.AES_CBC.decrypt(data, key.key, undefined, PrepareData(algCBC.iv, "iv"));
                    break;
                case AlgorithmNames.AesGCM:
                    const algGCM = algorithm;
                    algGCM.tagLength = algGCM.tagLength || 128;
                    let additionalData;
                    if (algGCM.additionalData) {
                        additionalData = PrepareData(algGCM.additionalData, "additionalData");
                    }
                    res = asmCrypto.AES_GCM.decrypt(data, key.key, algGCM.iv, additionalData, algGCM.tagLength / 8);
                    break;
                default:
                    throw new LinerError(AlgorithmError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
            return res.buffer;
        });
    }
    static wrapKey(format, key, wrappingKey, wrapAlgorithm) {
        let crypto;
        return Promise.resolve()
            .then(() => {
            crypto = new Crypto();
            return crypto.subtle.exportKey(format, key);
        })
            .then((data) => {
            let raw;
            if (!(data instanceof ArrayBuffer)) {
                // JWK
                raw = string2buffer(JSON.stringify(data));
            }
            else {
                // ArrayBuffer
                raw = new Uint8Array(data);
            }
            return crypto.subtle.encrypt(wrapAlgorithm, wrappingKey, raw);
        });
    }
    static unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
        let crypto;
        return Promise.resolve()
            .then(() => {
            crypto = new Crypto();
            return crypto.subtle.decrypt(unwrapAlgorithm, unwrappingKey, wrappedKey);
        })
            .then((data) => {
            let dataAny;
            if (format.toLowerCase() === "jwk") {
                dataAny = JSON.parse(buffer2string(new Uint8Array(data)));
            }
            else {
                dataAny = new Uint8Array(data);
            }
            return crypto.subtle.importKey(format, dataAny, unwrappedKeyAlgorithm, extractable, keyUsages);
        });
    }
    static alg2jwk(alg) {
        return `A${alg.length}${/-(\w+)/i.exec(alg.name.toUpperCase())[1]}`;
    }
    static jwk2alg(alg) {
        throw new Error("Not implemented");
    }
    static exportKey(format, key) {
        return Promise.resolve()
            .then(() => {
            const raw = key.key;
            if (format.toLowerCase() === "jwk") {
                const jwk = {
                    alg: this.alg2jwk(key.algorithm),
                    ext: key.extractable,
                    k: Base64Url.encode(raw),
                    key_ops: key.usages,
                    kty: "oct",
                };
                return jwk;
            }
            else {
                return raw.buffer;
            }
        });
    }
    static importKey(format, keyData, algorithm, extractable, usages) {
        return Promise.resolve()
            .then(() => {
            let raw;
            if (format.toLowerCase() === "jwk") {
                const jwk = keyData;
                raw = Base64Url.decode(jwk.k);
            }
            else {
                raw = new Uint8Array(keyData);
            }
            const key = new CryptoKey({
                type: "secret",
                algorithm,
                extractable,
                usages,
            });
            key.key = raw;
            return key;
        });
    }
    static checkModule() {
        if (typeof asmCrypto === "undefined") {
            throw new LinerError(LinerError.MODULE_NOT_FOUND, "asmCrypto", "https://github.com/vibornoff/asmcrypto.js");
        }
    }
}
import { Crypto } from "../crypto";
