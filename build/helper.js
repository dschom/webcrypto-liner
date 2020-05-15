export let Browser = {
    IE: "Internet Explorer",
    Safari: "Safari",
    Edge: "Edge",
    Chrome: "Chrome",
    Firefox: "Firefox Mozilla",
    Mobile: "Mobile",
};
/**
 * Returns info about browser
 */
export function BrowserInfo() {
    const res = {
        name: "Unknown",
        version: "0",
    };
    try {
        const userAgent = self.navigator.userAgent;
        let reg;
        // tslint:disable-next-line:no-conditional-assignment
        if (reg = /edge\/([\d\.]+)/i.exec(userAgent)) {
            res.name = Browser.Edge;
            res.version = reg[1];
        }
        else if (/msie/i.test(userAgent)) {
            res.name = Browser.IE;
            res.version = /msie ([\d\.]+)/i.exec(userAgent)[1];
        }
        else if (/Trident/i.test(userAgent)) {
            res.name = Browser.IE;
            res.version = /rv:([\d\.]+)/i.exec(userAgent)[1];
        }
        else if (/chrome/i.test(userAgent)) {
            res.name = Browser.Chrome;
            res.version = /chrome\/([\d\.]+)/i.exec(userAgent)[1];
        }
        else if (/safari/i.test(userAgent)) {
            res.name = Browser.Safari;
            res.version = /version\/([\d\.]+)/i.exec(userAgent)[1];
        }
        else if (/firefox/i.test(userAgent)) {
            res.name = Browser.Firefox;
            res.version = /firefox\/([\d\.]+)/i.exec(userAgent)[1];
        }
    }
    catch (e) { }
    return res;
}
export function string2buffer(binaryString) {
    const res = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        res[i] = binaryString.charCodeAt(i);
    }
    return res;
}
export function buffer2string(buffer) {
    let res = "";
    // tslint:disable-next-line:prefer-for-of
    for (let i = 0; i < buffer.length; i++) {
        res += String.fromCharCode(buffer[i]);
    }
    return res;
}
export function concat(...buf) {
    const res = new Uint8Array(buf.map((item) => item.length).reduce((prev, cur) => prev + cur));
    let offset = 0;
    buf.forEach((item, index) => {
        for (let i = 0; i < item.length; i++) {
            res[offset + i] = item[i];
        }
        offset += item.length;
    });
    return res;
}
export function assign(target, ...sources) {
    const res = arguments[0];
    for (let i = 1; i < arguments.length; i++) {
        const obj = arguments[i];
        for (const prop in obj) {
            res[prop] = obj[prop];
        }
    }
    return res;
}
export function warn(message, ...optionalParams) {
    if (typeof self !== "undefined" && self.PV_WEBCRYPTO_LINER_LOG) {
        console.warn.apply(console, arguments);
    }
}
