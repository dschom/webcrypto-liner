export class CryptoKey {
    constructor(options) {
        this.algorithm = options.algorithm;
        if (options.type) {
            this.type = options.type;
        }
        this.extractable = options.extractable;
        this.usages = options.usages;
    }
}
