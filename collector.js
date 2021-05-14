
// Collector source thanks to charlieAIO
// Modifications by wadu
// Mobile support by IdekDude

(function () {
    "use strict";

    var root = typeof window === "object" ? window : {};
    var NODE_JS =
        !root.JS_SHA1_NO_NODE_JS &&
        typeof process === "object" &&
        process.versions &&
        process.versions.node;
    if (NODE_JS) {
        root = global;
    }
    var COMMON_JS =
        !root.JS_SHA1_NO_COMMON_JS && typeof module === "object" && module.exports;
    var AMD = typeof define === "function" && define.amd;
    var HEX_CHARS = "0123456789abcdef".split("");
    var EXTRA = [-2147483648, 8388608, 32768, 128];
    var SHIFT = [24, 16, 8, 0];
    var OUTPUT_TYPES = ["hex", "array", "digest", "arrayBuffer"];

    var blocks = [];

    var createOutputMethod = function (outputType) {
        return function (message) {
            return new Sha1(true).update(message)[outputType]();
        };
    };

    var createMethod = function () {
        var method = createOutputMethod("hex");
        if (NODE_JS) {
            method = nodeWrap(method);
        }
        method.create = function () {
            return new Sha1();
        };
        method.update = function (message) {
            return method.create().update(message);
        };
        for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
            var type = OUTPUT_TYPES[i];
            method[type] = createOutputMethod(type);
        }
        return method;
    };

    var nodeWrap = function (method) {
        var crypto = eval("require('crypto')");
        var Buffer = eval("require('buffer').Buffer");
        var nodeMethod = function (message) {
            if (typeof message === "string") {
                return crypto.createHash("sha1").update(message, "utf8").digest("hex");
            } else if (message.constructor === ArrayBuffer) {
                message = new Uint8Array(message);
            } else if (message.length === undefined) {
                return method(message);
            }
            return crypto
                .createHash("sha1")
                .update(new Buffer(message))
                .digest("hex");
        };
        return nodeMethod;
    };

    function Sha1(sharedMemory) {
        if (sharedMemory) {
            blocks[0] = blocks[16] = blocks[1] = blocks[2] = blocks[3] = blocks[4] = blocks[5] = blocks[6] = blocks[7] = blocks[8] = blocks[9] = blocks[10] = blocks[11] = blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
            this.blocks = blocks;
        } else {
            this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        }

        this.h0 = 0x67452301;
        this.h1 = 0xefcdab89;
        this.h2 = 0x98badcfe;
        this.h3 = 0x10325476;
        this.h4 = 0xc3d2e1f0;

        this.block = this.start = this.bytes = this.hBytes = 0;
        this.finalized = this.hashed = false;
        this.first = true;
    }

    Sha1.prototype.update = function (message) {
        if (this.finalized) {
            return;
        }
        var notString = typeof message !== "string";
        if (notString && message.constructor === root.ArrayBuffer) {
            message = new Uint8Array(message);
        }
        var code,
            index = 0,
            i,
            length = message.length || 0,
            blocks = this.blocks;

        while (index < length) {
            if (this.hashed) {
                this.hashed = false;
                blocks[0] = this.block;
                blocks[16] = blocks[1] = blocks[2] = blocks[3] = blocks[4] = blocks[5] = blocks[6] = blocks[7] = blocks[8] = blocks[9] = blocks[10] = blocks[11] = blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
            }

            if (notString) {
                for (i = this.start; index < length && i < 64; ++index) {
                    blocks[i >> 2] |= message[index] << SHIFT[i++ & 3];
                }
            } else {
                for (i = this.start; index < length && i < 64; ++index) {
                    code = message.charCodeAt(index);
                    if (code < 0x80) {
                        blocks[i >> 2] |= code << SHIFT[i++ & 3];
                    } else if (code < 0x800) {
                        blocks[i >> 2] |= (0xc0 | (code >> 6)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                    } else if (code < 0xd800 || code >= 0xe000) {
                        blocks[i >> 2] |= (0xe0 | (code >> 12)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                    } else {
                        code =
                            0x10000 +
                            (((code & 0x3ff) << 10) | (message.charCodeAt(++index) & 0x3ff));
                        blocks[i >> 2] |= (0xf0 | (code >> 18)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | ((code >> 12) & 0x3f)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
                        blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
                    }
                }
            }

            this.lastByteIndex = i;
            this.bytes += i - this.start;
            if (i >= 64) {
                this.block = blocks[16];
                this.start = i - 64;
                this.hash();
                this.hashed = true;
            } else {
                this.start = i;
            }
        }
        if (this.bytes > 4294967295) {
            this.hBytes += (this.bytes / 4294967296) << 0;
            this.bytes = this.bytes % 4294967296;
        }
        return this;
    };

    Sha1.prototype.finalize = function () {
        if (this.finalized) {
            return;
        }
        this.finalized = true;
        var blocks = this.blocks,
            i = this.lastByteIndex;
        blocks[16] = this.block;
        blocks[i >> 2] |= EXTRA[i & 3];
        this.block = blocks[16];
        if (i >= 56) {
            if (!this.hashed) {
                this.hash();
            }
            blocks[0] = this.block;
            blocks[16] = blocks[1] = blocks[2] = blocks[3] = blocks[4] = blocks[5] = blocks[6] = blocks[7] = blocks[8] = blocks[9] = blocks[10] = blocks[11] = blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
        }
        blocks[14] = (this.hBytes << 3) | (this.bytes >>> 29);
        blocks[15] = this.bytes << 3;
        this.hash();
    };

    Sha1.prototype.hash = function () {
        var a = this.h0,
            b = this.h1,
            c = this.h2,
            d = this.h3,
            e = this.h4;
        var f,
            j,
            t,
            blocks = this.blocks;

        for (j = 16; j < 80; ++j) {
            t = blocks[j - 3] ^ blocks[j - 8] ^ blocks[j - 14] ^ blocks[j - 16];
            blocks[j] = (t << 1) | (t >>> 31);
        }

        for (j = 0; j < 20; j += 5) {
            f = (b & c) | (~b & d);
            t = (a << 5) | (a >>> 27);
            e = (t + f + e + 1518500249 + blocks[j]) << 0;
            b = (b << 30) | (b >>> 2);

            f = (a & b) | (~a & c);
            t = (e << 5) | (e >>> 27);
            d = (t + f + d + 1518500249 + blocks[j + 1]) << 0;
            a = (a << 30) | (a >>> 2);

            f = (e & a) | (~e & b);
            t = (d << 5) | (d >>> 27);
            c = (t + f + c + 1518500249 + blocks[j + 2]) << 0;
            e = (e << 30) | (e >>> 2);

            f = (d & e) | (~d & a);
            t = (c << 5) | (c >>> 27);
            b = (t + f + b + 1518500249 + blocks[j + 3]) << 0;
            d = (d << 30) | (d >>> 2);

            f = (c & d) | (~c & e);
            t = (b << 5) | (b >>> 27);
            a = (t + f + a + 1518500249 + blocks[j + 4]) << 0;
            c = (c << 30) | (c >>> 2);
        }

        for (; j < 40; j += 5) {
            f = b ^ c ^ d;
            t = (a << 5) | (a >>> 27);
            e = (t + f + e + 1859775393 + blocks[j]) << 0;
            b = (b << 30) | (b >>> 2);

            f = a ^ b ^ c;
            t = (e << 5) | (e >>> 27);
            d = (t + f + d + 1859775393 + blocks[j + 1]) << 0;
            a = (a << 30) | (a >>> 2);

            f = e ^ a ^ b;
            t = (d << 5) | (d >>> 27);
            c = (t + f + c + 1859775393 + blocks[j + 2]) << 0;
            e = (e << 30) | (e >>> 2);

            f = d ^ e ^ a;
            t = (c << 5) | (c >>> 27);
            b = (t + f + b + 1859775393 + blocks[j + 3]) << 0;
            d = (d << 30) | (d >>> 2);

            f = c ^ d ^ e;
            t = (b << 5) | (b >>> 27);
            a = (t + f + a + 1859775393 + blocks[j + 4]) << 0;
            c = (c << 30) | (c >>> 2);
        }

        for (; j < 60; j += 5) {
            f = (b & c) | (b & d) | (c & d);
            t = (a << 5) | (a >>> 27);
            e = (t + f + e - 1894007588 + blocks[j]) << 0;
            b = (b << 30) | (b >>> 2);

            f = (a & b) | (a & c) | (b & c);
            t = (e << 5) | (e >>> 27);
            d = (t + f + d - 1894007588 + blocks[j + 1]) << 0;
            a = (a << 30) | (a >>> 2);

            f = (e & a) | (e & b) | (a & b);
            t = (d << 5) | (d >>> 27);
            c = (t + f + c - 1894007588 + blocks[j + 2]) << 0;
            e = (e << 30) | (e >>> 2);

            f = (d & e) | (d & a) | (e & a);
            t = (c << 5) | (c >>> 27);
            b = (t + f + b - 1894007588 + blocks[j + 3]) << 0;
            d = (d << 30) | (d >>> 2);

            f = (c & d) | (c & e) | (d & e);
            t = (b << 5) | (b >>> 27);
            a = (t + f + a - 1894007588 + blocks[j + 4]) << 0;
            c = (c << 30) | (c >>> 2);
        }

        for (; j < 80; j += 5) {
            f = b ^ c ^ d;
            t = (a << 5) | (a >>> 27);
            e = (t + f + e - 899497514 + blocks[j]) << 0;
            b = (b << 30) | (b >>> 2);

            f = a ^ b ^ c;
            t = (e << 5) | (e >>> 27);
            d = (t + f + d - 899497514 + blocks[j + 1]) << 0;
            a = (a << 30) | (a >>> 2);

            f = e ^ a ^ b;
            t = (d << 5) | (d >>> 27);
            c = (t + f + c - 899497514 + blocks[j + 2]) << 0;
            e = (e << 30) | (e >>> 2);

            f = d ^ e ^ a;
            t = (c << 5) | (c >>> 27);
            b = (t + f + b - 899497514 + blocks[j + 3]) << 0;
            d = (d << 30) | (d >>> 2);

            f = c ^ d ^ e;
            t = (b << 5) | (b >>> 27);
            a = (t + f + a - 899497514 + blocks[j + 4]) << 0;
            c = (c << 30) | (c >>> 2);
        }

        this.h0 = (this.h0 + a) << 0;
        this.h1 = (this.h1 + b) << 0;
        this.h2 = (this.h2 + c) << 0;
        this.h3 = (this.h3 + d) << 0;
        this.h4 = (this.h4 + e) << 0;
    };

    Sha1.prototype.hex = function () {
        this.finalize();

        var h0 = this.h0,
            h1 = this.h1,
            h2 = this.h2,
            h3 = this.h3,
            h4 = this.h4;

        return (
            HEX_CHARS[(h0 >> 28) & 0x0f] +
            HEX_CHARS[(h0 >> 24) & 0x0f] +
            HEX_CHARS[(h0 >> 20) & 0x0f] +
            HEX_CHARS[(h0 >> 16) & 0x0f] +
            HEX_CHARS[(h0 >> 12) & 0x0f] +
            HEX_CHARS[(h0 >> 8) & 0x0f] +
            HEX_CHARS[(h0 >> 4) & 0x0f] +
            HEX_CHARS[h0 & 0x0f] +
            HEX_CHARS[(h1 >> 28) & 0x0f] +
            HEX_CHARS[(h1 >> 24) & 0x0f] +
            HEX_CHARS[(h1 >> 20) & 0x0f] +
            HEX_CHARS[(h1 >> 16) & 0x0f] +
            HEX_CHARS[(h1 >> 12) & 0x0f] +
            HEX_CHARS[(h1 >> 8) & 0x0f] +
            HEX_CHARS[(h1 >> 4) & 0x0f] +
            HEX_CHARS[h1 & 0x0f] +
            HEX_CHARS[(h2 >> 28) & 0x0f] +
            HEX_CHARS[(h2 >> 24) & 0x0f] +
            HEX_CHARS[(h2 >> 20) & 0x0f] +
            HEX_CHARS[(h2 >> 16) & 0x0f] +
            HEX_CHARS[(h2 >> 12) & 0x0f] +
            HEX_CHARS[(h2 >> 8) & 0x0f] +
            HEX_CHARS[(h2 >> 4) & 0x0f] +
            HEX_CHARS[h2 & 0x0f] +
            HEX_CHARS[(h3 >> 28) & 0x0f] +
            HEX_CHARS[(h3 >> 24) & 0x0f] +
            HEX_CHARS[(h3 >> 20) & 0x0f] +
            HEX_CHARS[(h3 >> 16) & 0x0f] +
            HEX_CHARS[(h3 >> 12) & 0x0f] +
            HEX_CHARS[(h3 >> 8) & 0x0f] +
            HEX_CHARS[(h3 >> 4) & 0x0f] +
            HEX_CHARS[h3 & 0x0f] +
            HEX_CHARS[(h4 >> 28) & 0x0f] +
            HEX_CHARS[(h4 >> 24) & 0x0f] +
            HEX_CHARS[(h4 >> 20) & 0x0f] +
            HEX_CHARS[(h4 >> 16) & 0x0f] +
            HEX_CHARS[(h4 >> 12) & 0x0f] +
            HEX_CHARS[(h4 >> 8) & 0x0f] +
            HEX_CHARS[(h4 >> 4) & 0x0f] +
            HEX_CHARS[h4 & 0x0f]
        );
    };

    Sha1.prototype.toString = Sha1.prototype.hex;

    Sha1.prototype.digest = function () {
        this.finalize();

        var h0 = this.h0,
            h1 = this.h1,
            h2 = this.h2,
            h3 = this.h3,
            h4 = this.h4;

        return [
            (h0 >> 24) & 0xff,
            (h0 >> 16) & 0xff,
            (h0 >> 8) & 0xff,
            h0 & 0xff,
            (h1 >> 24) & 0xff,
            (h1 >> 16) & 0xff,
            (h1 >> 8) & 0xff,
            h1 & 0xff,
            (h2 >> 24) & 0xff,
            (h2 >> 16) & 0xff,
            (h2 >> 8) & 0xff,
            h2 & 0xff,
            (h3 >> 24) & 0xff,
            (h3 >> 16) & 0xff,
            (h3 >> 8) & 0xff,
            h3 & 0xff,
            (h4 >> 24) & 0xff,
            (h4 >> 16) & 0xff,
            (h4 >> 8) & 0xff,
            h4 & 0xff,
        ];
    };

    Sha1.prototype.array = Sha1.prototype.digest;

    Sha1.prototype.arrayBuffer = function () {
        this.finalize();

        var buffer = new ArrayBuffer(20);
        var dataView = new DataView(buffer);
        dataView.setUint32(0, this.h0);
        dataView.setUint32(4, this.h1);
        dataView.setUint32(8, this.h2);
        dataView.setUint32(12, this.h3);
        dataView.setUint32(16, this.h4);
        return buffer;
    };

    var exports = createMethod();

    if (COMMON_JS) {
        module.exports = exports;
    } else {
        root.sha1 = exports;
        if (AMD) {
            define(function () {
                return exports;
            });
        }
    }
})();

const utils = {
    stringify: (function () {
        var e = Object["prototype"]["toString"],
            t =
                Array["isArray"] ||
                function (t) {
                    return "[object Array]" === e["call"](t);
                },
            n = {
                '"': '\\\\"',
                "\\": "\\\\\\\\",
                "\b": "\\\\b",
                "\f": "\\\\f",
                "\n": "\\\n",
                "\r": "\\\\r",
                "\t": "\\\t",
            },
            a = function (e) {
                return (
                    n[e] ||
                    "\\\\u" + (e["charCodeAt"](0) + 65536)["toString"](16)["substr"](1)
                );
            },
            r = /[\\"\u0000-\u001F\u2028\u2029]/g;

        return function n(i) {
            if (null == i) return "null";

            if ("number" == typeof i) return isFinite(i) ? i["toString"]() : "null";

            if ("boolean" == typeof i) return i["toString"]();

            if ("object" == typeof i) {
                if ("function" == typeof i["toJSON"]) return n(i["toJSON"]());

                if (t(i)) {
                    for (var o = "[", s = 0; s < i["length"]; s++)
                        o += (s ? ", " : "") + n(i[s]);

                    return o + "]";
                }

                if ("[object Object]" === e["call"](i)) {
                    var c = [];

                    for (var l in i)
                        i["hasOwnProperty"](l) && c["push"](n(l) + ": " + n(i[l]));

                    return "{" + c["join"](", ") + "}";
                }
            }

            return '"' + i["toString"]()["replace"](r, a) + '"';
        };
    })(),
};

const f = window;
const b = f.screen;
const u = f.document;

async function getBattery() {
    return new Promise((resolve, reject) => {
        if (!navigator.getBattery) {
            resolve(null);
        } else {
            navigator.getBattery().then(function (battery) {
                const toStringify = {};
                for (var a in battery) {
                    var r = battery[a];
                    toStringify[a] = r === 1 / 0 ? "Infinity" : r;
                }
                console.log(battery);
                console.log(utils.stringify(toStringify));
                resolve(utils.stringify(toStringify));
            });
        }
    });
}

async function harvest() {
    const bt = await getBattery();
    console.log(bt);
}

function writeToResult() { }

const fontList = [
    "Party LET",
    "Academy Engraved LET",
    "David",
    "Palatino Linotype",
    "Microsoft Sans Serif",
    "Segoe UI",
    "Malgun Gothic",
    "Nirmala UI",
    "Segoe Pseudo",
    "Gadugi",
    "Leelawadee UI Bold",
    "Sitka Subheading Italic",
    "Yu Gothic UI Light",
    "Bahnschrift",
    "Trattatello",
    "Skia",
    "Muna",
    "PingFang",
    "San Francisco UI",
    "San Francisco Mono",
    "Monotype LingWai Medium",
    "American Typewriter",
    "Rockwell",
    "Al Nile",
    "Roboto",
    "Noto",
    "Ubuntu",
    "Century Schoolbook L",
    "URW Chancery L",
    "URW Gothic L",
    "URW Bookman L",
    "Nimbus Mono L",
    "FreeMono",
    "FreeSans",
    "FreeSerif",
    "Bitstream Vera Sans",
    "Bitstream Charter",
    "Liberation Sans",
    "Liberation Serif",
    "Liberation Mono",
    "Luxi",
    "Nimbus Mono",
    "Nimbus Sans L",
    "Nimbus Roman No 9 L",
    "DejaVu Sans",
    "MONO",
    "DB LCD Temp",
    "Oriya Sangam MN",
    "Sinhala Sangam MN",
    "Apple Color Emoji",
    "Chalkboard",
    "Andale Mono",
    "Sitka Banner",
    "Segoe UI Emoji",
    "Leelawadee UI",
    "Vijaya",
    "Utsaah",
    "Shonar Bangla",
    "Aparajita",
    "Khmer UI",
    "Franklin Gothic",
    "MV Boli",
    "Corbel",
    "Cambria",
    "Segoe UI Light",
    "MS Gothic",
];
function getFonts(e) {
    return new Promise((resolve, reject) => {
        function t(e) {
            return (
                '<b style="position: absolute; display:inline !important; width:auto !important; font:normal 10px/1 ' +
                e +
                ' !important">wi wi</b>'
            );
        }

        function n(e) {
            return "<div>" + t([e, "monospace"]) + t([e, "sans-serif"]) + "</div>";
        }

        function a(e, t) {
            var n = e["childNodes"][0]["offsetWidth"];
            return n !== t || n === e["childNodes"][1]["offsetWidth"];
        }

        function r(e, t, r, i, o) {
            for (
                var s = "RYelrZVIUa", c = [], l = e["length"], f = "", u = 0;
                u < l;
                u++
            )
                f += n(t[e[u]]);

            if (
                (o && (f += n(s)), (r["innerHTML"] = f), o && a(r["childNodes"][l], i))
            )
                return null;

            for (u = 0; u < l; u++) a(r["childNodes"][u], i) && c["push"](e[u]);

            return c;
        }

        try {
            var l,
                f = [],
                b = !1,
                p = new Date()["valueOf"](),
                v = fontList["length"],
                g = [],
                m = [],
                O = document["body"],
                S = document["createElement"]("div"),
                A = document["createElement"]("div"),
                j = document["createElement"]("div");
            (S["style"]["cssText"] =
                "position: relative; left: -9999px; visibility: hidden; display: block !important"),
                (A["innerHTML"] = t(["monospace"])),
                S["appendChild"](A),
                S["appendChild"](j),
                O["insertBefore"](S, O["firstChild"]);
            var w = A["childNodes"][0]["offsetWidth"];
            0 === w && (b = !0);

            for (var y = 0; y < v; y++) y % 7 == 0 ? g["push"](y) : m["push"](y);

            if (
                ((l = r(g, fontList, j, w, !0)),
                    null === l
                        ? (b = !0)
                        : new Date()["valueOf"]() - p > 100
                            ? (d = !1)
                            : (f = r(m, fontList, j, w, !1)),
                    O["removeChild"](S),
                    b)
            ) {
                resolve(null);
            } else {
                console.log(f);
                var R = l["concat"](f);

                R["sort"](function (e, t) {
                    return e - t;
                }),
                    (R += ""),
                    resolve(R);
            }
        } catch (t) {
            console.log(t);
            try {
                O["removeChild"](S);
            } catch (e) { }
            resolve(null);
        }
    });
}

function getPlugins(e) {
    function c(e) {
        var t = 0;

        if (!e) return t;

        for (var n = 0; n < e["length"]; n++) {
            (t = (t << 5) - t + e["charCodeAt"](n)), (t &= t);
        }

        return t;
    }
    var t = [],
        a = navigator.plugins;

    if (a)
        for (var r = 0; r < a["length"]; r++)
            for (var o = 0; o < a[r]["length"]; o++)
                t["push"](
                    c(
                        [
                            a[r]["name"],
                            a[r]["description"],
                            a[r]["filename"],
                            a[r][o]["description"],
                            a[r][o]["type"],
                            a[r][o]["suffixes"],
                        ]["toString"]()
                    )
                );

    return t.toString();
}

function getScreenProperties() {
    try {
        var t = f["innerWidth"],
            n = f["outerWidth"],
            a = f["screenX"],
            r = f["pageXOffset"],
            o = b["availWidth"],
            s = b["width"],
            c = {
                inner: void 0 !== t ? [t, f["innerHeight"]] : 0,
                outer: void 0 !== n ? [n, f["outerHeight"]] : 0,
                screen: void 0 !== a ? [a, f["screenY"]] : 0,
                pageOffset: void 0 !== r ? [r, f["pageYOffset"]] : 0,
                avail: void 0 !== o ? [o, b["availHeight"]] : 0,
                size: void 0 !== s ? [s, b["height"]] : 0,
                client: u["body"]
                    ? [u["body"]["clientWidth"], u["body"]["clientHeight"]]
                    : -1,
                colorDepth: b["colorDepth"],
                pixelDepth: b["pixelDepth"],
            };

        return utils.stringify(c);
    } catch (t) {
        console.log(t);
        return null;
    }
}

function p(t, n) {
    function isArray(e) {
        return "[object Array]" === Object["prototype"]["toString"]["call"](e);
    }
    var a, r;
    return void 0 === t[n]
        ? 0
        : ((a = t[n]),
            (r = typeof a),
            !a || isArray(a) || ("object" !== r && "function" !== r) ? a : 1);
}
function enumerateObject(e, t, n) {
    console.log(e);
    n = n || {};

    for (var a = 0, r = t["length"]; a < r; a++)
        try {
            n[t[a]] = p(e, t[a]);
        } catch (err) {
            console.log(err);
            n[t[a]] = -1;
        }

    return n;
}

function getDocumentProperties() {
    try {
        var t = enumerateObject(f, [
            "XDomainRequest",
            "createPopup",
            "removeEventListener",
            "globalStorage",
            "openDatabase",
            "indexedDB",
            "attachEvent",
            "ActiveXObject",
            "dispatchEvent",
            "addBehavior",
            "addEventListener",
            "detachEvent",
            "fireEvent",
            "MutationObserver",
            "HTMLMenuItemElement",
            "Int8Array",
            "postMessage",
            "querySelector",
        ]);

        enumerateObject(
            u,
            [
                "getElementsByClassName",
                "querySelector",
                "images",
                "compatMode",
                "documentMode",
            ],
            t
        ),
            (t["all"] = +(void 0 !== u["all"])),
            f["performance"] && enumerateObject(f["performance"], ["now"], t),
            enumerateObject(u["documentElement"], ["contextMenu"], t);
        return utils.stringify(t);
    } catch (t) {
        return null;
    }
}

function getCanvasHash() {
    var t = !1;

    try {
        var n = u["createElement"]("canvas"),
            a = n["getContext"]("2d");
        (a["fillStyle"] = "rgba(255,153,153, 0.5)"),
            (a["font"] = "18pt Tahoma"),
            (a["textBaseline"] = "top"),
            a["fillText"]("Soft Ruddy Foothold 2", 2, 2),
            (a["fillStyle"] = "#0000FF"),
            a["fillRect"](100, 25, 30, 10),
            (a["fillStyle"] = "#E0E0E0"),
            a["fillRect"](100, 25, 20, 30),
            (a["fillStyle"] = "#FF3333"),
            a["fillRect"](100, 25, 10, 15),
            a["fillText"]("!H71JCaj)]# 1@#", 4, 8);
        var r = n["toDataURL"]();
        (u["createElement"]("img")["src"] = r), (t = sha1(r));
    } catch (e) { }

    return t;
}

function getSilverLightPlugin(e) {
    function t(e) {
        void 0 == e && (e = null);
        var t = !1;

        try {
            var n = !1;

            try {
                var a = d["plugins"]["Silverlight Plug-In"];

                if (a)
                    if (null === e) t = !0;
                    else {
                        for (
                            var r = a["description"], i = r["split"](".");
                            i["length"] > 3;

                        )
                            i["pop"]();

                        for (; i["length"] < 4;) i["push"](0);

                        for (var o = e["split"]("."); o["length"] > 4;) o["pop"]();

                        var s,
                            c,
                            l = 0;

                        do {
                            (s = f["parseInt"](o[l])), (c = f["parseInt"](i[l])), l++;
                        } while (l < o["length"] && s === c);

                        s <= c && !isNaN(s) && (t = !0);
                    }
                else n = !0;
            } catch (e) {
                n = !0;
            }

            if (n) {
                var u = new f["ActiveXObject"]("AgControl.AgControl");
                null === e ? (t = !0) : u["IsVersionSupported"](e) && (t = !0),
                    (u = null);
            }
        } catch (e) {
            t = !1;
        }

        return t;
    }

    try {
        for (
            var n = ["1.0", "2.0", "3.0", "4.0", "5.0"], a = [], r = 0;
            r < n["length"];
            r++
        )
            t(n[r]) && a["push"](n[r]);

        if (0 == a["length"]) return void !1;

        return a.join(",");
    } catch (t) {
        console.log(t);
        return null;
    }
}

function getActiveX(e) {
    if (f["ActiveXObject"]) {
        for (var t = 2; t < 10; t++)
            try {
                return !!new f["ActiveXObject"]("PDF.PdfCtrl." + t) && t;
            } catch (e) { }

        try {
            return !!new f["ActiveXObject"]("PDF.PdfCtrl.1") && "4";
        } catch (e) { }

        try {
            return !!new f["ActiveXObject"]("AcroPDF.PDF.1") && "7";
        } catch (e) { }
    }

    return !1;
}

function getJavascriptVersion(e) {
    var t = [
        "1.1",
        "1.2",
        "1.3",
        "1.4",
        "1.5",
        "1.6",
        "1.7",
        "1.8",
        "1.9",
        "2.0",
    ],
        n = "",
        a = "urhehlevkedkilrobacf";
    f[a] = "";

    try {
        for (
            var r = u["getElementsByTagName"]("head")[0], o = [], s = 0;
            s < t["length"];
            s++
        ) {
            var c = u["createElement"]("script"),
                l = t[s];
            c["setAttribute"]("language", "JavaScript" + l),
                (c["text"] = a + '="' + l + '"'),
                r["appendChild"](c),
                o["push"](c);
        }

        for (n = f[a], s = 0; s < t["length"]; s++) r["removeChild"](o[s]);
    } catch (e) { }

    return n;
}

function getNavValues(e) {
    try {
        var t = [
            "userAgent",
            "appName",
            "appCodeName",
            "appVersion",
            "appMinorVersion",
            "product",
            "productSub",
            "vendor",
            "vendorSub",
            "buildID",
            "platform",
            "oscpu",
            "hardwareConcurrency",
            "language",
            "languages",
            "systemLanguage",
            "userLanguage",
            "doNotTrack",
            "msDoNotTrack",
            "cookieEnabled",
            "geolocation",
            "vibrate",
            "maxTouchPoints",
            "webdriver",
        ],
            a = enumerateObject(f.navigator, t),
            r = navigator.plugins;

        if (r) {
            for (var o = [], s = 0, c = r["length"]; s < c; s++)
                o["push"](r[s]["name"]);

            a["plugins"] = o;
        }

        return utils.stringify(a);
    } catch (t) {
        console.log(t);
        return null;
    }
}

function getChromeProperties(e) {
    var t = {
        "window.chrome": window["chrome"] || "-not-existent",
    };

    return utils.stringify(t);
}

function getNavigatorProperties() {
    return new Promise((resolve, reject) => {
        var t = [],
            n = [
                "geolocation",
                "notifications",
                "push",
                "midi",
                "camera",
                "microphone",
                "speaker",
                "device-info",
                "background-sync",
                "bluetooth",
                "persistent-storage",
                "ambient-light-sensor",
                "accelerometer",
                "gyroscope",
                "magnetometer",
                "clipboard",
                "accessibility-events",
                "clipboard-read",
                "clipboard-write",
                "payment-handler",
            ];

        if (!navigator["permissions"]) return void resolve(6);

        try {
            var a = function (e, n) {
                return navigator["permissions"]
                ["query"]({
                    name: e,
                })
                ["then"](function (e) {
                    switch (e["state"]) {
                        case "prompt":
                            t[n] = 1;
                            break;
                        case "granted":
                            t[n] = 2;
                            break;
                        case "denied":
                            t[n] = 0;
                            break;
                        default:
                            t[n] = 5;
                    }
                })
                ["catch"](function (e) {
                    t[n] =
                        -1 !==
                            e["message"]["indexOf"](
                                "is not a valid enum value of type PermissionName"
                            )
                            ? 4
                            : 3;
                });
            },
                r = n["map"](function (e, t) {
                    return a(e, t);
                });

            Promise["all"](r)["then"](function () {
                resolve(t["join"](""));
            });
        } catch (t) {
            resolve(7);
        }
    });
}

async function doHarvest() {
    const battery = await getBattery();
    const fonts = await getFonts();
    const plugins = getPlugins();
    const screenProperties = getScreenProperties();
    const documentProperties = getDocumentProperties();
    const canvasHash = await getCanvasHash();
    const silverLight = getSilverLightPlugin();
    const activeX = getActiveX();
    const jsv = getJavascriptVersion();
    const navValues = getNavValues();
    const crc = getChromeProperties();
    const navProperties = await getNavigatorProperties();

    const toStringify = {
        battery: battery,
        fonts: fonts,
        plugins: plugins,
        screenProperties: screenProperties,
        documentProperties: documentProperties,
        canvasHash: canvasHash,
        silverLight: silverLight,
        activeX: activeX,
        jsVersion: jsv,
        navValues: navValues,
        crc: crc,
        navProperties: navProperties,
    };

    const toPost = JSON.stringify({ magic: toStringify });
    return toPost
};


t = {
    PLUGINS: [
        "WebEx64 General Plugin Container",
        "YouTube Plug-in",
        "Java Applet Plug-in",
        "Shockwave Flash",
        "iPhotoPhotocast",
        "SharePoint Browser Plug-in",
        "Chrome Remote Desktop Viewer",
        "Chrome PDF Viewer",
        "Native Client",
        "Unity Player",
        "WebKit-integrierte PDF",
        "QuickTime Plug-in",
        "RealPlayer Version Plugin",
        "RealPlayer(tm) G2 LiveConnect-Enabled Plug-In (32-bit)",
        "Mozilla Default Plug-in",
        "Adobe Acrobat",
        "AdobeAAMDetect",
        "Google Earth Plug-in",
        "Java Plug-in 2 for NPAPI Browsers",
        "Widevine Content Decryption Module",
        "Microsoft Office Live Plug-in",
        "Windows Media Player Plug-in Dynamic Link Library",
        "Google Talk Plugin Video Renderer",
        "Edge PDF Viewer",
        "Shockwave for Director",
        "Default Browser Helper",
        "Silverlight Plug-In",
    ],
    ins: null,
};
function sendError() {
    document.getElementById("code").style.backgroundColor = '#ffcccb'

    document.getElementById("image").src = "assets/angrycry.png";

    document.getElementById("statusMessage").style.color = "#A62122";

    document.getElementById("statusMessage").innerHTML = "Something went wrong!"

    document.getElementById("message2").style.color = "#A62122";

    document.getElementById("message2").innerHTML = "We couldn't send your data to our servers :'( "

}
var data = {}
function run() {

    if (window.speechSynthesis) {
        var a = window.speechSynthesis.getVoices();

        a = window.speechSynthesis.getVoices();

        a = window.speechSynthesis.getVoices();
    }



    while (!screen) {
        data.screen = window.screen
    }
    data.navigator = {}
    data.window = {}
    data.document = {}
    data.other = {}
    data.performance = performance


    data.navigator.appCodeName = navigator.appCodeName
    data.navigator.appName = navigator.appName
    data.navigator.appVersion = navigator.appVersion
    data.navigator.language = navigator.language
    data.navigator.languages = navigator.languages
    data.navigator.userAgent = navigator.userAgent
    data.navigator.vendor = navigator.vendor
    data.navigator.product = navigator.product
    data.navigator.productSub = navigator.productSub
    data.navigator.platform = navigator.platform

    data.navigator.vibrate = 'function' == typeof navigator['vibrate']
    data.navigator.getBattery = 'function' == typeof navigator['getBattery']
    data.navigator.credentials = Boolean(navigator['credentials'])
    data.navigator.appMinorVersion = Boolean(navigator['appMinorVersion'])
    data.navigator.bluetooth = Boolean(navigator['bluetooth'])
    data.navigator.storage = Boolean(navigator['storage'])
    data.navigator.getGamepads = Boolean(navigator['getGamepads'])
    data.navigator.getStorageUpdates = Boolean(navigator['getStorageUpdates'])
    data.navigator.hardwareConcurrency = Boolean(navigator['hardwareConcurrency'])
    data.navigator.mediaDevices = Boolean(navigator['mediaDevices'])
    data.navigator.mozAlarms = Boolean(navigator['mozAlarms'])
    data.navigator.mozConnection = Boolean(navigator['mozConnection'])
    data.navigator.mozIsLocallyAvailable = Boolean(navigator['mozIsLocallyAvailable'])
    data.navigator.mozPhoneNumberService = Boolean(navigator['mozPhoneNumberService'])
    data.navigator.msManipulationViewsEnabled = Boolean(navigator['msManipulationViewsEnabled'])
    data.navigator.permissions = Boolean(navigator['permissions'])
    data.navigator.registerProtocolHandler = Boolean(navigator['registerProtocolHandler'])
    data.navigator.requestMediaKeySystemAccess = Boolean(navigator['requestMediaKeySystemAccess'])
    data.navigator.requestWakeLock = Boolean(navigator['requestWakeLock'])
    data.navigator.sendBeacon = Boolean(navigator['sendBeacon'])
    data.navigator.serviceWorker = Boolean(navigator['serviceWorker'])
    data.navigator.storeWebWideTrackingException = Boolean(navigator['storeWebWideTrackingException'])
    data.navigator.webkitGetGamepads = Boolean(navigator['webkitGetGamepads'])
    data.navigator.webkitTemporaryStorage = Boolean(navigator['webkitTemporaryStorage'])
    data.navigator.cookieEnabled = navigator['cookieEnabled'] ? navigator['cookieEnabled'] : -1
    data.navigator.javaEnabled = navigator['javaEnabled'] ? navigator['javaEnabled']() : -1
    data.navigator.doNotTrack = navigator['doNotTrack'] ? navigator['doNotTrack'] : -1;

    data.window.ActiveXObject = Boolean(window['ActiveXObject']) || 'ActiveXObject' in window
    data.window.innerHeight = window.innerHeight;
    data.window.innerWidth = window.innerWidth;
    data.window.outerWidth = window.outerWidth;
    data.window.outerHeight = window.outerHeight;
    data.window.devicePixelRatio = window.devicePixelRatio;
    data.window.addEventListener = Boolean(window['addEventListener'])
    data.window.XMLHttpRequest = Boolean(window['XMLHttpRequest'])
    data.window.XDomainRequest = Boolean(window['XDomainRequest'])
    data.window.emit = window.emit
    data.window.orientation = typeof window['orientation'];
    data.window.DeviceOrientationEvent = Boolean(window['DeviceOrientationEvent'])
    data.window.DeviceMotionEvent = Boolean(window['DeviceMotionEvent'])
    data.window.TouchEvent = Boolean(window['TouchEvent'])
    data.window.spawn = window.spawn
    data.window.chrome = window.chrome
    data.window.prototype_bind = Boolean(Function['prototype']['bind'])
    data.window.Buffer = window.Buffer
    data.window.PointerEvent = Boolean(window['PointerEvent'])
    data.window._phantom = window._phantom
    data.window.webdriver = window.webdriver
    data.window.domAutomation = window.domAutomation
    data.window.callPhantom = window.callPhantom
    data.window.opera = window.opera
    data.window.sessionStorage = !!window['sessionStorage']
    data.window.localStorage = !!window['localStorage']
    data.window.indexedDB = !!window['indexedDB']
    data.window.FileReader = 'FileReader' in window
    data.window.HTMLElement = window['HTMLElement'] && Object['prototype']['toString']['call'](window['HTMLElement'])['indexOf']('Constructor') > 0
    data.window.webRTC = 'function' == typeof window['RTCPeerConnection'] || 'function' == typeof window['mozRTCPeerConnection'] || 'function' == typeof window['webkitRTCPeerConnection']
    data.window.mozInnerScreenY = 'mozInnerScreenY' in window ? window['mozInnerScreenY'] : 0

    data.document.documentMode = typeof document['documentMode']
    data.document.webdriver = window['document']['documentElement']['getAttribute']('webdriver') != null
    data.document.driver = window['document']['documentElement']['getAttribute']('driver') != null
    data.document.selenium = null != window['document']['documentElement']['getAttribute']('selenium')
    data.document.hidden = document['hidden']
    data.document.mozHidden = document['mozHidden']
    data.document.msHidden = document['msHidden']
    data.document.webkitHidden = document['webkitHidden']

    data.other.CC_ON = new Function('return/*@cc_on!@*/!1')()
    data.other.InstallTrigger = 'undefined' != typeof InstallTrigger
    data.other.prototype_forEach = Boolean(Array['prototype']['forEach'])
    data.other.imul = Boolean(Math['imul'])
    data.other.parseInt = Boolean(Number['parseInt'])
    data.other.hypot = Boolean(Math['hypot'])
    data.other.value1 = Boolean(window['$cdc_asdjflasutopfhvcZLmcfl_'] || document['$cdc_asdjflasutopfhvcZLmcfl_'])
    data.other.XPathResult = void 0 !== window['XPathResult'] || void 0 !== document['XPathResult']


    function plugins() {
        var plugins = [];

        for (var i = 0; i < navigator.plugins.length; i++) {

            plugins.push(navigator.plugins[i].name);

        }
        data.navigator.plugins = plugins
    }
    plugins()

    var rCFP = [];

    function canvas(a) {
        try {
            var e = -1;
            if (!sf4()) {
                var n = document.createElement("canvas");
                if (
                    ((n.width = 280),
                        (n.height = 60),
                        (n.style.display = "none"),
                        "function" == typeof n.getContext)
                ) {
                    var o = n.getContext("2d");
                    (o.fillStyle = "rgb(102, 204, 0)"),
                        o.fillRect(100, 5, 80, 50),
                        (o.fillStyle = "#f60"),
                        (o.font = "16pt Arial"),
                        o.fillText(a, 10, 40),
                        (o.strokeStyle = "rgb(120, 186, 176)"),
                        o.arc(80, 10, 20, 0, Math.PI, !1),
                        o.stroke();
                    var m = n.toDataURL();
                    e = 0;
                    for (var r = 0; r < m.length; r++) {
                        (e = (e << 5) - e + m.charCodeAt(r)), (e &= e);
                    }
                    e = e.toString();
                    var i = document.createElement("canvas");
                    (i.width = 16), (i.height = 16);
                    var c = i.getContext("2d");
                    (c.font = "6pt Arial"),
                        (rVal = Math.floor(1e3 * Math.random()).toString()),
                        c.fillText(rVal, 1, 12);
                    for (var b = i.toDataURL(), d = 0, k = 0; k < b.length; k++) {
                        (d = (d << 5) - d + b.charCodeAt(k)), (d &= d);
                    }
                    rCFP = d.toString();
                }
            }
            return e;
        } catch (a) {
            console.log(a);
            return "exception";
        }
    }
    function uar() {
        return window.navigator.userAgent.replace(/\\|"/g, "");
    }
    function sf4() {
        var a = uar();
        return !(
            !~a.indexOf("Version/4.0") ||
            !(
                ~a.indexOf("iPad;") ||
                ~a.indexOf("iPhone") ||
                ~a.indexOf("Mac OS X 10_5")
            )
        );
    }
    function fonts() {
        var a = [];
        if (!sf4() && document.body) {
            var e = ["serif", "sans-serif", "monospace"],
                n = [0, 0, 0],
                o = [0, 0, 0],
                m = document.createElement("span");
            (m.innerHTML = "abcdefhijklmnopqrstuvxyz1234567890;+-."),
                (m.style.fontSize = "90px");
            var r;
            for (r = 0; r < e.length; r++)
                (m.style.fontFamily = e[r]),
                    document.body.appendChild(m),
                    (n[r] = m.offsetWidth),
                    (o[r] = m.offsetHeight),
                    document.body.removeChild(m);
            for (
                var i = [
                    "Geneva",
                    "Lobster",
                    "New York",
                    "Century",
                    "Apple Gothic",
                    "Minion Pro",
                    "Apple LiGothic",
                    "Century Gothic",
                    "Monaco",
                    "Lato",
                    "Fantasque Sans Mono",
                    "Adobe Braille",
                    "Cambria",
                    "Futura",
                    "Bell MT",
                    "Courier",
                    "Courier New",
                    "Calibri",
                    "Avenir Next",
                    "Birch Std",
                    "Palatino",
                    "Ubuntu Regular",
                    "Oswald",
                    "Batang",
                    "Ubuntu Medium",
                    "Cantarell",
                    "Droid Serif",
                    "Roboto",
                    "Helvetica Neue",
                    "Corsiva Hebrew",
                    "Adobe Hebrew",
                    "TI-Nspire",
                    "Comic Neue",
                    "Noto",
                    "AlNile",
                    "Palatino-Bold",
                    "ArialHebrew-Light",
                    "Avenir",
                    "Papyrus",
                    "Open Sans",
                    "Times",
                    "Quicksand",
                    "Source Sans Pro",
                    "Damascus",
                    "Microsoft Sans Serif",
                ],
                c = [],
                b = 0;
                b < i.length;
                b++
            ) {
                var d = !1;
                for (r = 0; r < e.length; r++)
                    if (
                        ((m.style.fontFamily = i[b] + "," + e[r]),
                            document.body.appendChild(m),
                            (m.offsetWidth === n[r] && m.offsetHeight === o[r]) || (d = !0),
                            document.body.removeChild(m),
                            d)
                    ) {
                        c.push(b);
                        break;
                    }
            }
            a = c.sort();
        }
        return a.join(",");
    }
    function pluginInfo() {
        if (void 0 === navigator.plugins) return null;
        for (var a = t.PLUGINS.length, e = "", n = 0; n < a; n++) {
            var o = t.PLUGINS[n];
            void 0 !== navigator.plugins[o] && (e = e + "," + n);
        }
        return e;
    }
    function indexedDbKey() {
        return !!hasIndexedDB();
    }
    function sessionStorageKey() {
        return !!hasSessionStorage();
    }
    function localStorageKey() {
        return !!hasLocalStorage();
    }
    function hasSessionStorage() {
        try {
            return !!window.sessionStorage;
        } catch (a) {
            return !1;
        }
    }
    function hasLocalStorage() {
        try {
            return !!window.localStorage;
        } catch (a) {
            return !1;
        }
    }
    function hasIndexedDB() {
        return !!window.indexedDB;
    }
    function timezoneOffsetKey() {
        return new Date().getTimezoneOffset();
    }
    function webrtcKey() {
        return (
            "function" == typeof window.RTCPeerConnection ||
            "function" == typeof window.mozRTCPeerConnection ||
            "function" == typeof window.webkitRTCPeerConnection
        );
    }
    function get_cf_date() {
        return Date["now"] ? Date["now"]() : +new Date();
    }
    function fonts_optm() {
        var a = 200,
            e = get_cf_date(),
            n = [];
        if (!sf4() && document.body) {
            var o = ["sans-serif", "monospace"],
                m = [0, 0],
                r = [0, 0],
                i = document.createElement("div");
            i.style.cssText =
                "position: relative; left: -9999px; visibility: hidden; display: block !important";
            var c;
            for (c = 0; c < o.length; c++) {
                var b = document.createElement("span");
                (b.innerHTML = "abcdefhijklmnopqrstuvxyz1234567890;+-."),
                    (b.style.fontSize = "90px"),
                    (b.style.fontFamily = o[c]),
                    i.appendChild(b);
            }
            for (document.body.appendChild(i), c = 0; c < i.childNodes.length; c++)
                (b = i.childNodes[c]), (m[c] = b.offsetWidth), (r[c] = b.offsetHeight);
            if ((document.body.removeChild(i), get_cf_date() - e > a)) return "";
            var d = [
                "Geneva",
                "Lobster",
                "New York",
                "Century",
                "Apple Gothic",
                "Minion Pro",
                "Apple LiGothic",
                "Century Gothic",
                "Monaco",
                "Lato",
                "Fantasque Sans Mono",
                "Adobe Braille",
                "Cambria",
                "Futura",
                "Bell MT",
                "Courier",
                "Courier New",
                "Calibri",
                "Avenir Next",
                "Birch Std",
                "Palatino",
                "Ubuntu Regular",
                "Oswald",
                "Batang",
                "Ubuntu Medium",
                "Cantarell",
                "Droid Serif",
                "Roboto",
                "Helvetica Neue",
                "Corsiva Hebrew",
                "Adobe Hebrew",
                "TI-Nspire",
                "Comic Neue",
                "Noto",
                "AlNile",
                "Palatino-Bold",
                "ArialHebrew-Light",
                "Avenir",
                "Papyrus",
                "Open Sans",
                "Times",
                "Quicksand",
                "Source Sans Pro",
                "Damascus",
                "Microsoft Sans Serif",
            ],
                k = document.createElement("div");
            k.style.cssText =
                "position: relative; left: -9999px; visibility: hidden; display: block !important";
            for (var s = [], l = 0; l < d.length; l++) {
                var u = document.createElement("div");
                for (c = 0; c < o.length; c++) {
                    var b = document.createElement("span");
                    (b.innerHTML = "abcdefhijklmnopqrstuvxyz1234567890;+-."),
                        (b.style.fontSize = "90px"),
                        (b.style.fontFamily = d[l] + "," + o[c]),
                        u.appendChild(b);
                }
                k.appendChild(u);
            }
            if (get_cf_date() - e > a) return "";
            document.body.appendChild(k);
            for (var l = 0; l < k.childNodes.length; l++) {
                var _ = !1,
                    u = k.childNodes[l];
                for (c = 0; c < u.childNodes.length; c++) {
                    var b = u.childNodes[c];
                    if (b.offsetWidth !== m[c] || b.offsetHeight !== r[c]) {
                        _ = !0;
                        break;
                    }
                }
                if ((_ && s.push(l), get_cf_date() - e > a)) break;
            }
            document.body.removeChild(k), (n = s.sort());
        }
        return n.join(",");
    }
    function valStr() {
        var a = screen.colorDepth ? screen.colorDepth : -1,
            e = screen.pixelDepth ? screen.pixelDepth : -1,
            n = navigator.cookieEnabled ? navigator.cookieEnabled : -1,
            o = navigator.javaEnabled ? navigator.javaEnabled() : -1,
            m = navigator.doNotTrack ? navigator.doNotTrack : -1,
            r = "default";
        r = !1 ? (!1 ? fonts_optm() : fonts()) : "dis";
        data["fpValstr"] = [
            canvas("<@nv45. F1n63r,Pr1n71n6!"),
            canvas("m,Ev!xV67BaU> eh2m<f3AG3@"),
            r,
            pluginInfo(),
            sessionStorageKey(),
            localStorageKey(),
            indexedDbKey(),
            timezoneOffsetKey(),
            webrtcKey(),
            a,
            e,
            n,
            o,
            m,
        ]
            .join(";")
            .replace(/\"/g, '\\\\"');
    }
    function brave() {
        if (navigator.brave && navigator.brave.isBrave()) {
            data["brave"] = "1";
        } else {
            data["brave"] = "0";
        }
    }
    function csh() {
        if (window.speechSynthesis) {
            var a = window.speechSynthesis.getVoices();

            if (a.length > 0) {
                for (var t = "", e = 0; e < a.length; e++)
                    t += a[e].voiceURI + "_" + a[e].lang;

                data["ssh"] = ats(mn_s(t));
            } else data["ssh"] = "0";
        } else data["ssh"] = "n";
    }
    function getmr() {
        try {
            if (
                "undefined" == typeof performance ||
                void 0 === performance["now"] ||
                "undefined" == typeof JSON
            )
                return void (data["mr"] = "undef");

            for (
                var a = "",
                t = 1e3,
                e = [
                    Math["abs"],
                    Math["acos"],
                    Math["asin"],
                    Math["atanh"],
                    Math["cbrt"],
                    Math["exp"],
                    Math["random"],
                    Math["round"],
                    Math["sqrt"],
                    isFinite,
                    isNaN,
                    parseFloat,
                    parseInt,

                    JSON["parse"],
                ],
                n = 0;
                n < e["length"];
                n++
            ) {
                var o = [],
                    m = 0,
                    r = performance["now"](),
                    i = 0,
                    c = 0;

                if (void 0 !== e[n]) {
                    for (i = 0; i < t && m < 0.6; i++) {
                        for (var b = performance["now"](), d = 0; d < 4e3; d++) e[n](3.14);

                        var k = performance["now"]();

                        o["push"](Math["round"](1e3 * (k - b))), (m = k - r);
                    }

                    var l = o["sort"]();

                    c = l[Math["floor"](l["length"] / 2)] / 5;
                }

                a = a + c + ",";
            }

            data["mr"] = a;
        } catch (a) {
            data["mr"] = "exception";
        }
    }
    function wgl() {
        try {
            var a = document.createElement("canvas"),
                t = a.getContext("webgl");

            (data["wv"] = "n"),
                (data["wr"] = "n"),
                (data["weh"] = "n"),
                (data["wl"] = 0),
                t &&
                ((data["wv"] = "b"),
                    (data["wr"] = "b"),
                    (data["weh"] = "b"),
                    t.getSupportedExtensions() &&
                    ((data["weh"] = ats(
                        mn_s(JSON.stringify(t.getSupportedExtensions().sort()))
                    )),
                        (data["wl"] = t.getSupportedExtensions().length),
                        t.getSupportedExtensions().indexOf("WEBGL_debug_renderer_info") >=
                        0 &&
                        ((data["wv"] = t.getParameter(
                            t.getExtension("WEBGL_debug_renderer_info")
                                .UNMASKED_VENDOR_WEBGL
                        )),
                            (data["wr"] = t.getParameter(
                                t.getExtension("WEBGL_debug_renderer_info")
                                    .UNMASKED_RENDERER_WEBGL
                            )))));
        } catch (a) {
            (data["wv"] = "e"),
                (data["wr"] = "e"),
                (data["weh"] = "e"),
                (data["wl"] = 0);
        }
    }
    function np() {
        var a = [],
            t = [
                "geolocation",
                "notifications",
                "push",
                "midi",
                "camera",
                "microphone",
                "speaker",
                "device-info",
                "background-sync",
                "bluetooth",
                "persistent-storage",
                "ambient-light-sensor",
                "accelerometer",
                "gyroscope",
                "magnetometer",
                "clipboard",
                "accessibility-events",
                "clipboard-read",
                "clipboard-write",
                "payment-handler",
            ];

        try {
            if (!navigator["permissions"]) return 6;

            var e = function (t, e) {
                return navigator["permissions"]
                ["query"]({
                    name: t,
                })
                ["then"](function (t) {
                    switch (t["state"]) {
                        case "prompt":
                            a[e] = 1;

                            break;

                        case "granted":
                            a[e] = 2;

                            break;

                        case "denied":
                            a[e] = 0;

                            break;

                        default:
                            a[e] = 5;
                    }
                })
                ["catch"](function (t) {
                    a[e] =
                        -1 !==
                            t["message"]["indexOf"](
                                "is not a valid enum value of type PermissionName"
                            )
                            ? 4
                            : 3;
                });
            },
                n = t["map"](function (a, t) {
                    return e(a, t);
                });

            Promise["all"](n)["then"](function () {
                var N = a["join"]("");

                data["np"] = N;

                load();
            });
        } catch (a) {
            return 7;
        }
    }
    function ats(a) {
        for (var t = "", e = 0; e < a.length; e++)
            t +=
                2 == a[e].toString(16).length
                    ? a[e].toString(16)
                    : "0" + a[e].toString(16);

        return t;
    }
    function fm() {
        var a = [
            "Monospace",
            "Wingdings 2",
            "ITC Bodoni 72 Bold",
            "Menlo",
            "Gill Sans MT",
            "Lucida Sans",
            "Bodoni 72",
            "Serif",
            "Shree Devanagari 714",
            "Microsoft Tai Le",
            "Nimbus Roman No 9 L",
            "Candara",
            "Press Start 2P",
            "Waseem",
        ],
            t = document.createElement("span");

        (t.innerHTML = "mmmmmmmmlli"), (t.style.fontSize = "192px");

        var e = "",
            n = document.getElementsByTagName("body")[0];

        if (n) {
            for (var o in a)
                (t.style.fontFamily = a[o]),
                    n.appendChild(t),
                    (e += a[o] + ":" + t.offsetWidth + "," + t.offsetHeight + ";"),
                    n.removeChild(t);

            data["fmh"] = ats(mn_s(e));
        } else fmh = "";

        data["fmz"] =
            "devicePixelRatio" in window && void 0 !== window.devicePixelRatio
                ? window.devicePixelRatio
                : -1;
    }
    function mn_s(a) {
        var t = [
            1116352408,
            1899447441,
            3049323471,
            3921009573,
            961987163,
            1508970993,
            2453635748,
            2870763221,
            3624381080,
            310598401,
            607225278,
            1426881987,
            1925078388,
            2162078206,
            2614888103,
            3248222580,
            3835390401,
            4022224774,
            264347078,
            604807628,
            770255983,
            1249150122,
            1555081692,
            1996064986,
            2554220882,
            2821834349,
            2952996808,
            3210313671,
            3336571891,
            3584528711,
            113926993,
            338241895,
            666307205,
            773529912,
            1294757372,
            1396182291,
            1695183700,
            1986661051,
            2177026350,
            2456956037,
            2730485921,
            2820302411,
            3259730800,
            3345764771,
            3516065817,
            3600352804,
            4094571909,
            275423344,
            430227734,
            506948616,
            659060556,
            883997877,
            958139571,
            1322822218,
            1537002063,
            1747873779,
            1955562222,
            2024104815,
            2227730452,
            2361852424,
            2428436474,
            2756734187,
            3204031479,
            3329325298,
        ],
            e = 1779033703,
            n = 3144134277,
            o = 1013904242,
            m = 2773480762,
            r = 1359893119,
            i = 2600822924,
            c = 528734635,
            b = 1541459225,
            d = encode_utf8(a),
            k = 8 * d.length;

        d += String.fromCharCode(128);

        for (
            var s = d.length / 4 + 2, l = Math.ceil(s / 16), u = new Array(l), _ = 0;
            _ < l;
            _++
        ) {
            u[_] = new Array(16);

            for (var f = 0; f < 16; f++)
                u[_][f] =
                    (d.charCodeAt(64 * _ + 4 * f) << 24) |
                    (d.charCodeAt(64 * _ + 4 * f + 1) << 16) |
                    (d.charCodeAt(64 * _ + 4 * f + 2) << 8) |
                    (d.charCodeAt(64 * _ + 4 * f + 3) << 0);
        }

        var p = k / Math.pow(2, 32);

        (u[l - 1][14] = Math.floor(p)), (u[l - 1][15] = k);

        for (var v = 0; v < l; v++) {
            for (
                var h,
                g = new Array(64),
                w = e,
                y = n,
                E = o,
                S = m,
                C = r,
                h = i,
                M = c,
                x = b,
                _ = 0;
                _ < 64;
                _++
            ) {
                var j, A, L, P, T, D;

                _ < 16
                    ? (g[_] = u[v][_])
                    : ((j =
                        rotate_right(g[_ - 15], 7) ^
                        rotate_right(g[_ - 15], 18) ^
                        (g[_ - 15] >>> 3)),
                        (A =
                            rotate_right(g[_ - 2], 17) ^
                            rotate_right(g[_ - 2], 19) ^
                            (g[_ - 2] >>> 10)),
                        (g[_] = g[_ - 16] + j + g[_ - 7] + A)),
                    (A = rotate_right(C, 6) ^ rotate_right(C, 11) ^ rotate_right(C, 25)),
                    (L = (C & h) ^ (~C & M)),
                    (P = x + A + L + t[_] + g[_]),
                    (j = rotate_right(w, 2) ^ rotate_right(w, 13) ^ rotate_right(w, 22)),
                    (T = (w & y) ^ (w & E) ^ (y & E)),
                    (D = j + T),
                    (x = M),
                    (M = h),
                    (h = C),
                    (C = (S + P) >>> 0),
                    (S = E),
                    (E = y),
                    (y = w),
                    (w = (P + D) >>> 0);
            }

            (e += w),
                (n += y),
                (o += E),
                (m += S),
                (r += C),
                (i += h),
                (c += M),
                (b += x);
        }

        return [
            (e >> 24) & 255,
            (e >> 16) & 255,
            (e >> 8) & 255,
            255 & e,
            (n >> 24) & 255,
            (n >> 16) & 255,
            (n >> 8) & 255,
            255 & n,
            (o >> 24) & 255,
            (o >> 16) & 255,
            (o >> 8) & 255,
            255 & o,
            (m >> 24) & 255,
            (m >> 16) & 255,
            (m >> 8) & 255,
            255 & m,
            (r >> 24) & 255,
            (r >> 16) & 255,
            (r >> 8) & 255,
            255 & r,
            (i >> 24) & 255,
            (i >> 16) & 255,
            (i >> 8) & 255,
            255 & i,
            (c >> 24) & 255,
            (c >> 16) & 255,
            (c >> 8) & 255,
            255 & c,
            (b >> 24) & 255,
            (b >> 16) & 255,
            (b >> 8) & 255,
            255 & b,
        ];
    }
    function rotate_right(a, t) {
        return (a >>> t) | (a << (32 - t));
    }

    function encode_utf8(a) {
        return unescape(encodeURIComponent(a));
    }




    data["canvas"] = {
        value1: canvas("<@nv45. F1n63r,Pr1n71n6!"),

        value2: canvas("m,Ev!xV67BaU> eh2m<f3AG3@"),
    };
    data["fonts_optm"] = fonts_optm();

    data["fonts"] = fonts();

    data["rCFP"] = rCFP

    csh();

    getmr();

    brave();

    wgl();

    fm();

    csh();

    valStr();

    async function post(data) {
        console.log("if you're reading this, chav check")
        console.log(data)
        toPost = await doHarvest()

        try {
            response = fetch("https://rattenfanger.io/data/collect", {
                method: "POST",
                mode: "cors",
                headers: {
                    "content-type": "application/json",
                },
                body: JSON.stringify({
                    "SENSOR": data,
                    "PIXEL:": toPost
                })
            });
            document.getElementById("statusMessage").innerHTML = "Thank you!"

            document.getElementById("message2").innerHTML = "We have successfully collected all of the data we needed. We promise we won't use it in a bad way."
            return
        } catch (error) {
            console.log(error)

            sendError()

        }


    }

    function load() {
        setTimeout(function () {
            post(data);
        }, 5000);
    }

    setTimeout(function () {
        csh();
    }, 5000);

    setTimeout(function () {
        data.screen = {}
        data.screen.availHeight = screen.availHeight
        data.screen.availLeft = screen.availLeft
        data.screen.availTop = screen.availTop
        data.screen.availWidth = screen.availWidth
        data.screen.colorDepth = screen.colorDepth
        data.screen.height = screen.height
        data.screen.pixelDepth = screen.pixelDepth
        data.screen.width = screen.width
    }, 250);

    np();

}
/*
if (typeof window.orientation !== 'undefined') {
  document.getElementById('statusMessage').innerHTML = 'Unfortunately, we do not support mobile yet!'
  document.getElementById('message2').innerHTML = 'But thanks for trying <3'
} else {*/
window.onload = function () {
    setTimeout(function () {
        run();
    }, 2000);

}
