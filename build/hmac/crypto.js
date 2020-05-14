import { BaseCrypto, Base64Url } from "webcrypto-core";
import { CryptoKey } from "../key";
export class HmacCrypto extends BaseCrypto {
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
                usages
            });
            key.key = raw;
            return key;
        });
    }
    static sign(algorithm, key, data) {
        return Promise.resolve()
            .then(() => {
            // TODO other hashes
            const res = asmCrypto.HMAC_SHA256.bytes(data, key.key);
            return res.buffer;
        });
    }
    static exportKey(format, key) {
        return Promise.resolve()
            .then(() => {
            const raw = key.key;
            if (format.toLowerCase() === "jwk") {
                const jwk = {
                    alg: "HS256",
                    kty: "oct",
                    k: Base64Url.encode(raw),
                    key_ops: key.usages,
                    ext: key.extractable
                };
                return jwk;
            }
            else {
                return raw.buffer;
            }
        }); //TODO jwk
    }
}
