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
  
  function writeToResult() {}
  
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
        } catch (e) {}
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
    } catch (e) {}
  
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
  
              for (; i["length"] < 4; ) i["push"](0);
  
              for (var o = e["split"]("."); o["length"] > 4; ) o["pop"]();
  
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
        } catch (e) {}
  
      try {
        return !!new f["ActiveXObject"]("PDF.PdfCtrl.1") && "4";
      } catch (e) {}
  
      try {
        return !!new f["ActiveXObject"]("AcroPDF.PDF.1") && "7";
      } catch (e) {}
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
    } catch (e) {}
  
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
  
    fetch("/echo", {
      headers: {
        "Content-Type": "application/json",
      },
      method: "POST",
      body: toPost,
    })
      .then(async function (res) {
        document.querySelector("#message").textContent = await res.text();
      })
      .catch(function (res) {
        document.querySelector("#message").textContent = res;
      });
  }
  doHarvest();
