import { SubtleCrypto } from "./subtle";
import { nativeCrypto } from "./init";
export class Crypto {
    constructor() {
        this.subtle = new SubtleCrypto();
    }
    getRandomValues(array) {
        return nativeCrypto.getRandomValues(array);
    }
}
