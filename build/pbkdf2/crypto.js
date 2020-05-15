import { BaseCrypto, AlgorithmNames } from "webcrypto-core";
import { LinerError } from "../error";
import { CryptoKey } from "../key";
export class Pbkdf2Crypto extends BaseCrypto {
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
            const iterations = algorithm.iterations;
            const bytes = length / 8;
            const hash = typeof (algorithm.hash) === 'string' ? algorithm.hash : algorithm.hash.name;
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
