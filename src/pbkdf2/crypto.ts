import { BaseCrypto, AlgorithmNames } from "webcrypto-core";
import { LinerError } from "../error";
import { CryptoKey } from "../key";

export class Pbkdf2Crypto extends BaseCrypto {
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

    public static deriveBits(algorithm: Pbkdf2Params, baseKey: CryptoKey, length: number): PromiseLike<ArrayBuffer> {
        return Promise.resolve()
            .then(() => {
                let res: Uint8Array;
                const salt = new Uint8Array(algorithm.salt as ArrayBuffer);
                const iterations = algorithm.iterations;
                const bytes = length / 8;
                const hash = typeof(algorithm.hash) === 'string' ? algorithm.hash : algorithm.hash.name;
                switch (hash.toUpperCase()) {
                    case AlgorithmNames.Sha512.toUpperCase():
                        res = asmCrypto.PBKDF2_HMAC_SHA512.bytes(baseKey.key, salt, iterations, bytes);
                        break;
                    case AlgorithmNames.Sha256.toUpperCase():
                        res = asmCrypto.PBKDF2_HMAC_SHA256.bytes(baseKey.key, salt, iterations, bytes);
                        break;
                    case AlgorithmNames.Sha1.toUpperCase():
                        res = asmCrypto.PBKDF2_HMAC_SHA1.bytes(baseKey.key, salt, iterations, bytes);
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