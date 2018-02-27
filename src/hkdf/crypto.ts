import { BaseCrypto, AlgorithmNames } from "webcrypto-core";
import { LinerError } from "../error";
import { CryptoKey } from "../key";

function extract(key: Uint8Array, salt: Uint8Array) {
    return asmCrypto.HMAC_SHA256.bytes(key, salt)
}

function expand(prk: Uint8Array, length: number, info: Uint8Array) {
    const hlen = prk.length;
    const steps = Math.ceil(length / hlen)
    const t = new Uint8Array(hlen * steps + info.length + 1)
    let start = 0
    let end = 0
    for (let i = 0; i < steps; i++) {
        t.set(info, end)
        t[end + info.length] = (i + 1);
        const h = asmCrypto.HMAC_SHA256.bytes(t.slice(start, end + info.length + 1), prk)
        t.set(h, end)
        start = end
        end += hlen
    }
    return t.slice(0, length)
}

function hkdf(key: Uint8Array, length: number, salt: Uint8Array, info: Uint8Array) {
    const prk = extract(key, salt);
    return expand(prk, length, info);
}

export class HkdfCrypto extends BaseCrypto {
    public static importKey(format: string, keyData: JsonWebKey | Uint8Array, algorithm: Algorithm, extractable: boolean, usages: string[]): PromiseLike<CryptoKey> {
        return Promise.resolve()
            .then(() => {
                const raw = new Uint8Array(keyData as Uint8Array);
                const key = new CryptoKey({
                    type: "secret",
                    algorithm,
                    extractable,
                    usages
                })
                key.key = raw;
                return key;
            })
    }

    public static deriveBits(algorithm: any, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        return Promise.resolve()
            .then(() => {
                let res: Uint8Array;
                const salt = new Uint8Array(algorithm.salt as ArrayBuffer);
                const info = new Uint8Array(algorithm.info as ArrayBuffer);
                const bytes = length / 8;
                const hash = typeof(algorithm.hash) === 'string' ? algorithm.hash : algorithm.hash.name;
                switch (hash.toUpperCase()) {
                    case AlgorithmNames.Sha256.toUpperCase():
                        res = hkdf(baseKey.key, bytes, salt, info)
                        break;
                    default:
                        throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, hash);

                }
                return res.buffer;
            });
    }

    public static deriveKey(algorithm: Pbkdf2Params, baseKey: CryptoKey, derivedKeyType: Algorithm, extractable: boolean, keyUsages: string[]): PromiseLike<CryptoKey> {
        return Promise.resolve()
            .then(() => {
                let length = 0;
                switch (derivedKeyType.name.toUpperCase()) {
                    case AlgorithmNames.AesCBC.toUpperCase():
                    case AlgorithmNames.AesCTR.toUpperCase():
                    case AlgorithmNames.AesGCM.toUpperCase():
                    case AlgorithmNames.AesKW.toUpperCase():
                        length = (derivedKeyType as AesDerivedKeyParams).length;
                        break;
                    case AlgorithmNames.Hmac.toUpperCase():
                        length = 512; // TODO
                        break;
                    default:
                        throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, derivedKeyType.name)
                }
                return this.deriveBits(algorithm, baseKey, length)
            })
            .then((bits: ArrayBuffer) => {
                const crypto = new Crypto();
                return crypto.subtle.importKey("raw", new Uint8Array(bits), derivedKeyType, extractable, keyUsages);
            })
    }
}

import { Crypto } from "../crypto";