import { BaseCrypto, AlgorithmNames, Base64Url } from "webcrypto-core";
import { LinerError } from "../error";
import { CryptoKey } from "../key";

export class HmacCrypto extends BaseCrypto {
    public static importKey(format: string, keyData: JsonWebKey | Uint8Array, algorithm: Algorithm, extractable: boolean, usages: string[]): PromiseLike<CryptoKey> {
        return Promise.resolve()
            .then(() => {
                let raw: Uint8Array;
                if (format.toLowerCase() === "jwk") {
                    const jwk = keyData as JsonWebKey;
                    raw = Base64Url.decode(jwk.k!);
                } else {
                    raw = new Uint8Array(keyData as Uint8Array);
                }
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

    public static sign(algorithm: Algorithm, key: CryptoKey, data: Uint8Array): PromiseLike<ArrayBuffer> {
        return Promise.resolve()
            .then(() => {
                // TODO other hashes
                const res = asmCrypto.HMAC_SHA256.bytes(data, key.key)
                return res.buffer;
            })
    }

    public static exportKey(format: string, key: CryptoKey): PromiseLike<JsonWebKey | ArrayBuffer> {
        return Promise.resolve()
            .then(() => {
                const raw = key.key;
                if (format.toLowerCase() === "jwk") {
                    const jwk: JsonWebKey = {
                        alg: "HS256",
                        kty: "oct",
                        k: Base64Url.encode(raw),
                        key_ops: key.usages,
                        ext: key.extractable
                    }
                    return jwk;
                } else {
                    return raw.buffer
                }
            }) //TODO jwk
    }
}