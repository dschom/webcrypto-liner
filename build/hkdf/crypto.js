import { BaseCrypto, AlgorithmNames } from "webcrypto-core";
import { LinerError } from "../error";
import { CryptoKey } from "../key";
function extract(key, salt) {
    return asmCrypto.HMAC_SHA256.bytes(key, salt);
}
function expand(prk, length, info) {
    const hlen = prk.length;
    const steps = Math.ceil(length / hlen);
    const t = new Uint8Array(hlen * steps + info.length + 1);
    let start = 0;
    let end = 0;
    for (let i = 0; i < steps; i++) {
        t.set(info, end);
        t[end + info.length] = (i + 1);
        const h = asmCrypto.HMAC_SHA256.bytes(t.slice(start, end + info.length + 1), prk);
        t.set(h, end);
        start = end;
        end += hlen;
    }
    return t.slice(0, length);
}
function hkdf(key, length, salt, info) {
    const prk = extract(key, salt);
    return expand(prk, length, info);
}
export class HkdfCrypto extends BaseCrypto {
    static importKey(format, keyData, algorithm, extractable, usages) {
        return Promise.resolve()
            .then(() => {
            const raw = new Uint8Array(keyData);
            const key = new CryptoKey({
                type: "secret",
                algorithm,
                extractable,
                usages
            });
            key.key = raw;
            return key;
        });
    }
    static deriveBits(algorithm, baseKey, length) {
        return Promise.resolve()
            .then(() => {
            let res;
            const salt = new Uint8Array(algorithm.salt);
            const info = new Uint8Array(algorithm.info);
            const bytes = length / 8;
            const hash = typeof (algorithm.hash) === 'string' ? algorithm.hash : algorithm.hash.name;
            switch (hash.toUpperCase()) {
                case AlgorithmNames.Sha256.toUpperCase():
                    res = hkdf(baseKey.key, bytes, salt, info);
                    break;
                default:
                    throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, hash);
            }
            return res.buffer;
        });
    }
    static deriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
        return Promise.resolve()
            .then(() => {
            let length = 0;
            switch (derivedKeyType.name.toUpperCase()) {
                case AlgorithmNames.AesCBC.toUpperCase():
                case AlgorithmNames.AesCTR.toUpperCase():
                case AlgorithmNames.AesGCM.toUpperCase():
                case AlgorithmNames.AesKW.toUpperCase():
                    length = derivedKeyType.length;
                    break;
                case AlgorithmNames.Hmac.toUpperCase():
                    length = 512; // TODO
                    break;
                default:
                    throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, derivedKeyType.name);
            }
            return this.deriveBits(algorithm, baseKey, length);
        })
            .then((bits) => {
            const crypto = new Crypto();
            return crypto.subtle.importKey("raw", new Uint8Array(bits), derivedKeyType, extractable, keyUsages);
        });
    }
}
import { Crypto } from "../crypto";
