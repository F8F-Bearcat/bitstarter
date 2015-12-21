"use strict";
var sjcl = {
    cipher: {},
    hash: {},
    mode: {},
    misc: {},
    codec: {},
    exception: {
        corrupt: function(a) {
            this.toString = function() {
                return "CORRUPT: " + this.message;
            };
            this.message = a;
        },
        invalid: function(a) {
            this.toString = function() {
                return "INVALID: " + this.message;
            };
            this.message = a;
        },
        bug: function(a) {
            this.toString = function() {
                return "BUG: " + this.message;
            };
            this.message = a;
        },
        notReady: function(a) {
            this.toString = function() {
                return "NOT READY: " + this.message;
            };
            this.message = a;
        }
    }
};

sjcl.bitArray = {
    bitSlice: function(a, b, c) {
        a = sjcl.bitArray.P(a.slice(b / 32), 32 - (b & 31)).slice(1);
        return c === undefined ? a : sjcl.bitArray.clamp(a, c - b);
    },
    concat: function(a, b) {
        if (a.length === 0 || b.length === 0) return a.concat(b);
        var c = a[a.length - 1],
            d = sjcl.bitArray.getPartial(c);
        return d === 32 ? a.concat(b) : sjcl.bitArray.P(b, d, c | 0, a.slice(0, a.length - 1));
    },
    bitLength: function(a) {
        var b = a.length;
        if (b === 0) return 0;
        return (b - 1) * 32 + sjcl.bitArray.getPartial(a[b - 1]);
    },
    clamp: function(a, b) {
        if (a.length * 32 < b) return a;
        a = a.slice(0, Math.ceil(b /
            32));
        var c = a.length;
        b &= 31;
        if (c > 0 && b) a[c - 1] = sjcl.bitArray.partial(b, a[c - 1] & 2147483648 >> b - 1, 1);
        return a;
    },
    partial: function(a, b, c) {
        if (a === 32) return b;
        return (c ? b | 0 : b << 32 - a) + a * 0x10000000000;
    },
    getPartial: function(a) {
        return Math.round(a / 0x10000000000) || 32;
    },
    equal: function(a, b) {
        if (sjcl.bitArray.bitLength(a) !== sjcl.bitArray.bitLength(b)) return false;
        var c = 0,
            d;
        for (d = 0; d < a.length; d++) c |= a[d] ^ b[d];
        return c === 0;
    },
    P: function(a, b, c, d) {
        var e;
        e = 0;
        if (d === undefined) d = [];
        for (; b >= 32; b -= 32) {
            d.push(c);
            c = 0;
        }
        if (b === 0) return d.concat(a);
        for (e = 0; e < a.length; e++) {
            d.push(c | a[e] >>> b);
            c = a[e] << 32 - b;
        }
        e = a.length ? a[a.length - 1] : 0;
        a = sjcl.bitArray.getPartial(e);
        d.push(sjcl.bitArray.partial(b + a & 31, b + a > 32 ? c : d.pop(), 1));
        return d;
    },
    k: function(a, b) {
        return [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]];
    }
};
sjcl.codec.utf8String = {
    fromBits: function(a) {
        var b = "",
            c = sjcl.bitArray.bitLength(a),
            d, e;
        for (d = 0; d < c / 8; d++) {
            if ((d & 3) === 0) e = a[d / 4];
            b += String.fromCharCode(e >>> 24);
            e <<= 8;
        }
        return decodeURIComponent(escape(b));
    },
    toBits: function(a) {
        a = unescape(encodeURIComponent(a));
        var b = [],
            c, d = 0;
        for (c = 0; c < a.length; c++) {
            d = d << 8 | a.charCodeAt(c);
            if ((c & 3) === 3) {
                b.push(d);
                d = 0;
            }
        }
        c & 3 && b.push(sjcl.bitArray.partial(8 * (c & 3), d));
        return b;
    }
};

sjcl.codec.base64 = {
    F: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    fromBits: function(a, b) {
        var c = "",
            d, e = 0,
            f = sjcl.codec.base64.F,
            g = 0,
            h = sjcl.bitArray.bitLength(a);
        for (d = 0; c.length * 6 < h;) {
            c += f.charAt((g ^ a[d] >>> e) >>> 26);
            if (e < 6) {
                g = a[d] << 6 - e;
                e += 26;
                d++;
            } else {
                g <<= 6;
                e -= 6;
            }
        }
        for (; c.length & 3 && !b;) c += "=";
        return c;
    },
    toBits: function(a) {
        a = a.replace(/\s|=/g, "");
        var b = [],
            c, d = 0,
            e = sjcl.codec.base64.F,
            f = 0,
            g;
        for (c = 0; c < a.length; c++) {
            g = e.indexOf(a.charAt(c));
            if (g < 0) throw new sjcl.exception.invalid("this isn't base64!");
            if (d > 26) {
                d -= 26;
                b.push(f ^ g >>> d);
                f = g << 32 - d;
            } else {
                d += 6;
                f ^= g << 32 - d;
            }
        }
        d & 56 && b.push(sjcl.bitArray.partial(d & 56, f, 1));
        return b;
    }
};
sjcl.hash.sha256 = function(a) {
    this.a[0] || this.z();
    if (a) {
        this.n = a.n.slice(0);
        this.i = a.i.slice(0);
        this.e = a.e;
    } else this.reset();
};
sjcl.hash.sha256.hash = function(a) {
    return (new sjcl.hash.sha256).update(a).finalize();
};

sjcl.hash.sha256.prototype = {
    blockSize: 512,
    reset: function() {
        this.n = this.N.slice(0);
        this.i = [];
        this.e = 0;
        return this;
    },
    update: function(a) {
        if (typeof a === "string") a = sjcl.codec.utf8String.toBits(a);
        var b, c = this.i = sjcl.bitArray.concat(this.i, a);
        b = this.e;
        a = this.e = b + sjcl.bitArray.bitLength(a);
        for (b = 512 + b & -512; b <= a; b += 512) this.D(c.splice(0, 16));
        return this;
    },
    finalize: function() {
        var a, b = this.i,
            c = this.n;
        b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1, 1)]);
        for (a = b.length + 2; a & 15; a++) b.push(0);
        b.push(Math.floor(this.e /
            4294967296));
        for (b.push(this.e | 0); b.length;) this.D(b.splice(0, 16));
        this.reset();
        return c;
    },
    N: [],
    a: [],
    z: function() {
        function a(e) {
            return (e - Math.floor(e)) * 0x100000000 | 0;
        }
        var b = 0,
            c = 2,
            d;
        a: for (; b < 64; c++) {
            for (d = 2; d * d <= c; d++)
                if (c % d === 0) continue a;
            if (b < 8) this.N[b] = a(Math.pow(c, 0.5));
            this.a[b] = a(Math.pow(c, 1 / 3));
            b++;
        }
    },
    D: function(a) {
        var b, c, d = a.slice(0),
            e = this.n,
            f = this.a,
            g = e[0],
            h = e[1],
            i = e[2],
            k = e[3],
            j = e[4],
            l = e[5],
            m = e[6],
            n = e[7];
        for (a = 0; a < 64; a++) {
            if (a < 16) b = d[a];
            else {
                b = d[a + 1 & 15];
                c = d[a + 14 & 15];
                b = d[a & 15] = (b >>> 7 ^ b >>> 18 ^
                    b >>> 3 ^ b << 25 ^ b << 14) + (c >>> 17 ^ c >>> 19 ^ c >>> 10 ^ c << 15 ^ c << 13) + d[a & 15] + d[a + 9 & 15] | 0;
            }
            b = b + n + (j >>> 6 ^ j >>> 11 ^ j >>> 25 ^ j << 26 ^ j << 21 ^ j << 7) + (m ^ j & (l ^ m)) + f[a];
            n = m;
            m = l;
            l = j;
            j = k + b | 0;
            k = i;
            i = h;
            h = g;
            g = b + (h & i ^ k & (h ^ i)) + (h >>> 2 ^ h >>> 13 ^ h >>> 22 ^ h << 30 ^ h << 19 ^ h << 10) | 0;
        }
        e[0] = e[0] + g | 0;
        e[1] = e[1] + h | 0;
        e[2] = e[2] + i | 0;
        e[3] = e[3] + k | 0;
        e[4] = e[4] + j | 0;
        e[5] = e[5] + l | 0;
        e[6] = e[6] + m | 0;
        e[7] = e[7] + n | 0;
    }
};

var crypto = require("crypto");
var sha256 = crypto.createHash("sha256").update("Apple").digest("base64");
console.log("Node crypto sha256 with base64 digest is " + sha256);

var out = sjcl.hash.sha256.hash("Apple");
var hash = sjcl.codec.base64.fromBits(out);
console.log("Stanford javascript crypto sha256 w base64 digest is " + hash);
console.log(sha256==hash);