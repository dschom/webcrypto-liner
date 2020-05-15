import { WebCryptoError } from "webcrypto-core";
export class LinerError extends WebCryptoError {
    constructor() {
        super(...arguments);
        this.code = 10;
    }
}
LinerError.MODULE_NOT_FOUND = "Module '%1' is not found. Download it from %2";
LinerError.UNSUPPORTED_ALGORITHM = "Unsupported algorithm '%1'";
