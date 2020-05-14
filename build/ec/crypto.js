import { BaseCrypto, AlgorithmNames, Base64Url } from "webcrypto-core";
import { LinerError } from "../error";
import { CryptoKey } from "../key";
import { concat } from "../helper";
import * as elliptic from "@dannycoates/elliptic";
// Helper
function b2a(buffer) {
    const buf = new Uint8Array(buffer);
    const res = [];
    // tslint:disable-next-line:prefer-for-of
    for (let i = 0; i < buf.length; i++) {
        res.push(buf[i]);
    }
    return res;
}
function hex2buffer(hexString, padded) {
    if (hexString.length % 2) {
        hexString = "0" + hexString;
    }
    let res = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < hexString.length; i++) {
        const c = hexString.slice(i, ++i + 1);
        res[(i - 1) / 2] = parseInt(c, 16);
    }
    // BN padding
    if (padded) {
        let len = res.length;
        len = len > 32 ? len > 48 ? 66 : 48 : 32;
        if (res.length < len) {
            res = concat(new Uint8Array(len - res.length), res);
        }
    }
    return res;
}
function buffer2hex(buffer, padded) {
    let res = "";
    // tslint:disable-next-line:prefer-for-of
    for (let i = 0; i < buffer.length; i++) {
        const char = buffer[i].toString(16);
        res += char.length % 2 ? "0" + char : char;
    }
    // BN padding
    if (padded) {
        let len = buffer.length;
        len = len > 32 ? len > 48 ? 66 : 48 : 32;
        if ((res.length / 2) < len) {
            res = new Array(len * 2 - res.length + 1).join("0") + res;
        }
    }
    return res;
}
export class EcCrypto extends BaseCrypto {
    static generateKey(algorithm, extractable, keyUsage) {
        return Promise.resolve()
            .then(() => {
            this.checkModule();
            const alg = algorithm;
            const key = new elliptic.ec(this.getNamedCurve(algorithm.namedCurve));
            // set key params
            const prvKey = new CryptoKey({
                type: "private",
                algorithm,
                extractable,
                usages: [],
            });
            const pubKey = new CryptoKey({
                type: "public",
                algorithm,
                extractable: true,
                usages: [],
            });
            prvKey.key = pubKey.key = key.genKeyPair();
            if (algorithm.name === AlgorithmNames.EcDSA) {
                prvKey.usages = ["sign"];
                pubKey.usages = ["verify"];
            }
            else if (algorithm.name === AlgorithmNames.EcDH) {
                prvKey.usages = ["deriveKey", "deriveBits"];
                pubKey.usages = [];
            }
            return {
                privateKey: prvKey,
                publicKey: pubKey,
            };
        });
    }
    static sign(algorithm, key, data) {
        return Promise.resolve()
            .then(() => {
            const alg = algorithm;
            // get digest
            const crypto = new Crypto();
            return crypto.subtle.digest(alg.hash, data);
        })
            .then((hash) => {
            const array = b2a(hash);
            const signature = key.key.sign(array);
            const hexSignature = buffer2hex(signature.r.toArray(), true) + buffer2hex(signature.s.toArray(), true);
            return hex2buffer(hexSignature).buffer;
        });
    }
    static verify(algorithm, key, signature, data) {
        let sig;
        return Promise.resolve()
            .then(() => {
            const alg = algorithm;
            sig = {
                r: signature.slice(0, signature.byteLength / 2),
                s: signature.slice(signature.byteLength / 2),
            };
            // get digest
            const crypto = new Crypto();
            return crypto.subtle.digest(alg.hash, data);
        })
            .then((hash) => {
            const array = b2a(hash);
            return (key.key.verify(array, sig));
        });
    }
    static deriveKey(algorithm, baseKey, derivedKeyType, extractable, keyUsages) {
        return Promise.resolve()
            .then(() => this.deriveBits(algorithm, baseKey, derivedKeyType.length))
            .then((bits) => {
            const crypto = new Crypto();
            return crypto.subtle.importKey("raw", new Uint8Array(bits), derivedKeyType, extractable, keyUsages);
        });
    }
    static deriveBits(algorithm, baseKey, length) {
        return Promise.resolve()
            .then(() => {
            const promise = Promise.resolve(null);
            const shared = baseKey.key.derive(algorithm.public.key.getPublic());
            let array = new Uint8Array(shared.toArray());
            // Padding
            let len = array.length;
            len = (len > 32 ? (len > 48 ? 66 : 48) : 32);
            if (array.length < len) {
                array = concat(new Uint8Array(len - array.length), array);
            }
            const buf = array.slice(0, length / 8).buffer;
            return buf;
        });
    }
    static exportKey(format, key) {
        return Promise.resolve()
            .then(() => {
            const ecKey = key.key;
            if (format.toLowerCase() === "jwk") {
                const hexPub = ecKey.getPublic("hex").slice(2); // ignore first '04'
                const hexX = hexPub.slice(0, hexPub.length / 2);
                const hexY = hexPub.slice(hexPub.length / 2, hexPub.length);
                if (key.type === "public") {
                    // public
                    const jwk = {
                        crv: key.algorithm.namedCurve,
                        ext: key.extractable,
                        x: Base64Url.encode(hex2buffer(hexX, true)),
                        y: Base64Url.encode(hex2buffer(hexY, true)),
                        key_ops: key.usages,
                        kty: "EC",
                    };
                    return jwk;
                }
                else {
                    // private
                    const jwk = {
                        crv: key.algorithm.namedCurve,
                        ext: key.extractable,
                        d: Base64Url.encode(hex2buffer(ecKey.getPrivate("hex"), true)),
                        x: Base64Url.encode(hex2buffer(hexX, true)),
                        y: Base64Url.encode(hex2buffer(hexY, true)),
                        key_ops: key.usages,
                        kty: "EC",
                    };
                    return jwk;
                }
            }
            else {
                throw new LinerError(`Format '${format}' is not implemented`);
            }
        });
    }
    static importKey(format, keyData, algorithm, extractable, usages) {
        return Promise.resolve()
            .then(() => {
            const key = new CryptoKey({
                algorithm,
                extractable,
                usages,
            });
            if (format.toLowerCase() === "jwk") {
                const namedCurve = this.getNamedCurve(algorithm.namedCurve);
                console.log(namedCurve);
                const ecKey = new elliptic.ec(namedCurve);
                if (keyData.d) {
                    // Private key
                    key.key = ecKey.keyFromPrivate(Base64Url.decode(keyData.d));
                    key.type = "private";
                }
                else {
                    // Public key
                    const bufferPubKey = concat(new Uint8Array([4]), Base64Url.decode(keyData.x), Base64Url.decode(keyData.y));
                    const hexPubKey = buffer2hex(bufferPubKey);
                    key.key = ecKey.keyFromPublic(hexPubKey, "hex");
                    key.type = "public";
                }
            }
            else {
                throw new LinerError(`Format '${format}' is not implemented`);
            }
            return key;
        });
    }
    static checkModule() {
        if (typeof elliptic === "undefined") {
            throw new LinerError(LinerError.MODULE_NOT_FOUND, "elliptic", "https://github.com/indutny/elliptic");
        }
    }
    static getNamedCurve(wcNamedCurve) {
        const crv = wcNamedCurve.toUpperCase();
        let res = "";
        if (["P-256", "P-384", "P-521"].indexOf(crv) > -1) {
            res = crv.replace("-", "").toLowerCase();
        }
        else if (crv === "K-256") {
            res = "secp256k1";
        }
        else {
            throw new LinerError(`Unsupported named curve '${wcNamedCurve}'`);
        }
        return res;
    }
}
import { Crypto } from "../crypto";
