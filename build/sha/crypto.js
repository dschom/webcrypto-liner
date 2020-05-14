import { BaseCrypto, AlgorithmNames } from "webcrypto-core";
import { LinerError } from "../error";
export class ShaCrypto extends BaseCrypto {
    static digest(alg, message) {
        return Promise.resolve()
            .then(() => {
            if (typeof asmCrypto === "undefined") {
                throw new LinerError(LinerError.MODULE_NOT_FOUND, "asmCrypto", "https://github.com/vibornoff/asmcrypto.js");
            }
            switch (alg.name.toUpperCase()) {
                case AlgorithmNames.Sha1:
                    return asmCrypto.SHA1.bytes(message).buffer;
                case AlgorithmNames.Sha256:
                    return asmCrypto.SHA256.bytes(message).buffer;
                case AlgorithmNames.Sha512:
                    return asmCrypto.SHA512.bytes(message).buffer;
                default:
                    throw new LinerError(`Not supported algorithm '${alg.name}'`);
            }
        });
    }
}
