import { AlgorithmError, AlgorithmNames, Base64Url, BaseCrypto, PrepareData } from "webcrypto-core";
import { LinerError } from "../error";
import { buffer2string, string2buffer } from "../helper";
import { CryptoKey } from "../key";
function removeLeadingZero(buf) {
    let first = true;
    return buf.filter((v) => {
        if (first && v === 0) {
            return false;
        }
        else {
            first = false;
            return true;
        }
    });
}
export class RsaCrypto extends BaseCrypto {
    static generateKey(algorithm, extractable, keyUsage) {
        return Promise.resolve()
            .then(() => {
            this.checkModule();
            const pubExp = algorithm.publicExponent[0] === 3 ? 3 : 65537;
            const rsaKey = asmCrypto.RSA.generateKey(algorithm.modulusLength, pubExp);
            const privateKey = new CryptoKey({
                type: "private",
                algorithm,
                extractable,
                usages: [],
            });
            const publicKey = new CryptoKey({
                type: "public",
                algorithm,
                extractable: true,
                usages: [],
            });
            privateKey.key = publicKey.key = rsaKey;
            switch (algorithm.name.toLowerCase()) {
                case AlgorithmNames.RsaOAEP.toLowerCase():
                    privateKey.usages = this.filterUsages(["decrypt", "unwrapKey"], keyUsage);
                    publicKey.usages = this.filterUsages(["encrypt", "wrapKey"], keyUsage);
                    break;
                case AlgorithmNames.RsaSSA.toLowerCase():
                case AlgorithmNames.RsaPSS.toLowerCase():
                    privateKey.usages = this.filterUsages(["sign"], keyUsage);
                    publicKey.usages = this.filterUsages(["verify"], keyUsage);
                    break;
                default:
                    throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
            return { privateKey, publicKey };
        });
    }
    static sign(algorithm, key, data) {
        return Promise.resolve()
            .then(() => {
            switch (algorithm.name.toLowerCase()) {
                case AlgorithmNames.RsaSSA.toLowerCase(): {
                    const keyAlg = key.algorithm;
                    const rsaAlg = algorithm;
                    let sign;
                    switch (keyAlg.hash.name.toUpperCase()) {
                        case AlgorithmNames.Sha1:
                            sign = asmCrypto.RSA_PKCS1_v1_5_SHA1.sign;
                            break;
                        case AlgorithmNames.Sha256:
                            sign = asmCrypto.RSA_PKCS1_v1_5_SHA256.sign;
                            break;
                        case AlgorithmNames.Sha512:
                            sign = asmCrypto.RSA_PKCS1_v1_5_SHA512.sign;
                            break;
                        default:
                            throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
                    }
                    return sign(data, key.key).buffer;
                }
                case AlgorithmNames.RsaPSS.toLowerCase(): {
                    const keyAlg = key.algorithm;
                    const rsaAlg = algorithm;
                    let sign;
                    switch (keyAlg.hash.name.toUpperCase()) {
                        case AlgorithmNames.Sha1:
                            sign = asmCrypto.RSA_PSS_SHA1.sign;
                            break;
                        case AlgorithmNames.Sha256:
                            sign = asmCrypto.RSA_PSS_SHA256.sign;
                            break;
                        case AlgorithmNames.Sha512:
                            sign = asmCrypto.RSA_PSS_SHA512.sign;
                            break;
                        default:
                            throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
                    }
                    return sign(data, key.key, rsaAlg.saltLength).buffer;
                }
                default:
                    throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
        });
    }
    static verify(algorithm, key, signature, data) {
        return Promise.resolve()
            .then(() => {
            switch (algorithm.name.toLowerCase()) {
                case AlgorithmNames.RsaSSA.toLowerCase(): {
                    const keyAlg = key.algorithm;
                    const rsaAlg = algorithm;
                    let verify;
                    switch (keyAlg.hash.name.toUpperCase()) {
                        case AlgorithmNames.Sha1:
                            verify = asmCrypto.RSA_PKCS1_v1_5_SHA1.verify;
                            break;
                        case AlgorithmNames.Sha256:
                            verify = asmCrypto.RSA_PKCS1_v1_5_SHA256.verify;
                            break;
                        case AlgorithmNames.Sha512:
                            verify = asmCrypto.RSA_PKCS1_v1_5_SHA512.verify;
                            break;
                        default:
                            throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
                    }
                    try {
                        return verify(signature, data, key.key);
                    }
                    catch (err) {
                        console.warn(`Verify error: ${err.message}`);
                        return false;
                    }
                }
                case AlgorithmNames.RsaPSS.toLowerCase():
                    const keyAlg = key.algorithm;
                    const rsaAlg = algorithm;
                    let verify;
                    switch (keyAlg.hash.name.toUpperCase()) {
                        case AlgorithmNames.Sha1:
                            verify = asmCrypto.RSA_PSS_SHA1.verify;
                            break;
                        case AlgorithmNames.Sha256:
                            verify = asmCrypto.RSA_PSS_SHA256.verify;
                            break;
                        case AlgorithmNames.Sha512:
                            verify = asmCrypto.RSA_PSS_SHA512.verify;
                            break;
                        default:
                            throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, key.algorithm.name);
                    }
                    try {
                        return verify(signature, data, key.key, rsaAlg.saltLength);
                    }
                    catch (err) {
                        console.warn(`Verify error: ${err.message}`);
                        return false;
                    }
                default:
                    throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
        });
    }
    static encrypt(algorithm, key, data) {
        return Promise.resolve()
            .then(() => {
            switch (algorithm.name.toLowerCase()) {
                case AlgorithmNames.RsaOAEP.toLowerCase():
                    const keyAlg = key.algorithm;
                    const rsaAlg = algorithm;
                    let encrypt;
                    switch (keyAlg.hash.name.toUpperCase()) {
                        case AlgorithmNames.Sha1:
                            encrypt = asmCrypto.RSA_OAEP_SHA1.encrypt;
                            break;
                        case AlgorithmNames.Sha256:
                            encrypt = asmCrypto.RSA_OAEP_SHA256.encrypt;
                            break;
                        case AlgorithmNames.Sha512:
                            encrypt = asmCrypto.RSA_OAEP_SHA512.encrypt;
                            break;
                        default:
                            throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, `${keyAlg.name} ${keyAlg.hash.name}`);
                    }
                    let label;
                    if (rsaAlg.label) {
                        label = PrepareData(rsaAlg.label, "label");
                    }
                    return encrypt(data, key.key, label);
                default:
                    throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
        });
    }
    static decrypt(algorithm, key, data) {
        return Promise.resolve()
            .then(() => {
            switch (algorithm.name.toLowerCase()) {
                case AlgorithmNames.RsaOAEP.toLowerCase():
                    const keyAlg = key.algorithm;
                    const rsaAlg = algorithm;
                    let decrypt;
                    switch (keyAlg.hash.name.toUpperCase()) {
                        case AlgorithmNames.Sha1:
                            decrypt = asmCrypto.RSA_OAEP_SHA1.decrypt;
                            break;
                        case AlgorithmNames.Sha256:
                            decrypt = asmCrypto.RSA_OAEP_SHA256.decrypt;
                            break;
                        case AlgorithmNames.Sha512:
                            decrypt = asmCrypto.RSA_OAEP_SHA512.decrypt;
                            break;
                        default:
                            throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, `${keyAlg.name} ${keyAlg.hash.name}`);
                    }
                    let label;
                    if (rsaAlg.label) {
                        label = PrepareData(rsaAlg.label, "label");
                    }
                    return decrypt(data, key.key, label);
                default:
                    throw new LinerError(LinerError.UNSUPPORTED_ALGORITHM, algorithm.name);
            }
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
            let preparedData;
            if (format.toLowerCase() === "jwk") {
                preparedData = JSON.parse(buffer2string(new Uint8Array(data)));
            }
            else {
                preparedData = new Uint8Array(data);
            }
            return crypto.subtle.importKey(format, preparedData, unwrappedKeyAlgorithm, extractable, keyUsages);
        });
    }
    static alg2jwk(alg) {
        const hash = alg.hash;
        const hashSize = /(\d+)/.exec(hash.name)[1];
        switch (alg.name.toUpperCase()) {
            case AlgorithmNames.RsaOAEP.toUpperCase():
                return `RSA-OAEP${hashSize === "1" ? "" : `-${hashSize}`}`;
            case AlgorithmNames.RsaPSS.toUpperCase():
                return `PS${hashSize}`;
            case AlgorithmNames.RsaSSA.toUpperCase():
                return `RS${hashSize}`;
            default:
                throw new AlgorithmError(AlgorithmError.UNSUPPORTED_ALGORITHM, alg.name);
        }
    }
    static jwk2alg(alg) {
        throw new Error("Not implemented");
    }
    static exportKey(format, key) {
        return Promise.resolve()
            .then(() => {
            if (format.toLowerCase() === "jwk") {
                const jwk = {
                    kty: "RSA",
                    ext: true,
                    key_ops: key.usages,
                };
                jwk.alg = this.alg2jwk(key.algorithm);
                jwk.n = Base64Url.encode(removeLeadingZero(key.key[0]));
                jwk.e = Base64Url.encode(removeLeadingZero(key.key[1]));
                if (key.type === "private") {
                    jwk.d = Base64Url.encode(removeLeadingZero(key.key[2]));
                    jwk.p = Base64Url.encode(removeLeadingZero(key.key[3]));
                    jwk.q = Base64Url.encode(removeLeadingZero(key.key[4]));
                    jwk.dp = Base64Url.encode(removeLeadingZero(key.key[5]));
                    jwk.dq = Base64Url.encode(removeLeadingZero(key.key[6]));
                    jwk.qi = Base64Url.encode(removeLeadingZero(key.key[7]));
                }
                return jwk;
            }
            else {
                throw new LinerError(LinerError.NOT_SUPPORTED);
            }
        });
    }
    static importKey(format, keyData, algorithm, extractable, usages) {
        return Promise.resolve()
            .then(() => {
            let jwk;
            const key = new CryptoKey({
                algorithm,
                extractable,
                usages,
            });
            key.key = [];
            if (format.toLowerCase() === "jwk") {
                jwk = keyData;
                key.key[0] = Base64Url.decode(jwk.n);
                key.key[1] = Base64Url.decode(jwk.e)[0] === 3 ? new Uint8Array([0, 0, 0, 3]) : new Uint8Array([0, 1, 0, 1]);
                if (jwk.d) {
                    key.type = "private";
                    key.key[2] = Base64Url.decode(jwk.d);
                    key.key[3] = Base64Url.decode(jwk.p);
                    key.key[4] = Base64Url.decode(jwk.q);
                    key.key[5] = Base64Url.decode(jwk.dp);
                    key.key[6] = Base64Url.decode(jwk.dq);
                    key.key[7] = Base64Url.decode(jwk.qi);
                }
                else {
                    key.type = "public";
                }
                return key;
            }
            else {
                throw new LinerError(LinerError.NOT_SUPPORTED);
            }
        });
    }
    static checkModule() {
        if (typeof asmCrypto === "undefined") {
            throw new LinerError(LinerError.MODULE_NOT_FOUND, "asmCrypto", "https://github.com/vibornoff/asmcrypto.js");
        }
    }
    static filterUsages(supported, given) {
        return supported.filter((item1) => !!given.filter((item2) => item1 === item2).length);
    }
}
import { Crypto } from "../crypto";
