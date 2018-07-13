(function(window){
"use strict";

function _toConsumableArray(arr) { if (Array.isArray(arr)) { for (var i = 0, arr2 = Array(arr.length); i < arr.length; i++) { arr2[i] = arr[i]; } return arr2; } else { return Array.from(arr); } }

// adapted from https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-08#appendix-C

function base64urlEncode(arg) {
  var step1 = window.btoa(arg); // Regular base64 encoder
  var step2 = step1.split("=")[0]; // Remove any trailing '='s
  var step3 = step2.replace(/\+/g, "-"); // 62nd char of encoding
  var step4 = step3.replace(/\//g, "_"); // 63rd char of encoding
  return step4;
}

function base64urlDecode(s) {
  var step1 = s.replace(/-/g, "+"); // 62nd char of encoding
  var step2 = step1.replace(/_/g, "/"); // 63rd char of encoding
  var step3 = step2;
  switch (step2.length % 4) {// Pad with trailing '='s
    case 0:
      // No pad chars in this case
      break;
    case 2:
      // Two pad chars
      step3 += "==";
      break;
    case 3:
      // One pad char
      step3 += "=";
      break;
    default:
      throw new Error("Illegal base64url string!");
  }
  return window.atob(step3); // Regular base64 decoder
}

var _module = window.module || {};
_module.exports = { base64urlDecode: base64urlDecode, base64urlEncode: base64urlEncode };
/* eslint no-bitwise: 0 */
/* global base64urlDecode */

function arrayToString(a) {
  return String.fromCharCode.apply(null, a);
}

function stringToArray(s) {
  return s.split("").map(function (c) {
    return c.charCodeAt();
  });
}

function base64urlToArray(s) {
  return stringToArray(base64urlDecode(s));
}

function pemToArray(pem) {
  return stringToArray(window.atob(pem));
}

function arrayToPem(a) {
  return window.btoa(a.map(function (c) {
    return String.fromCharCode(c);
  }).join(""));
}

function arrayToLen(a) {
  var result = 0;
  for (var i = 0; i < a.length; i += 1) {
    result = result * 256 + a[i];
  }
  return result;
}

function integerToOctet(n) {
  var result = [];
  for (var i = n; i > 0; i >>= 8) {
    result.push(i & 0xff);
  }
  return result.reverse();
}

function lenToArray(n) {
  var oct = integerToOctet(n);
  var i = void 0;
  for (i = oct.length; i < 4; i += 1) {
    oct.unshift(0);
  }
  return oct;
}

function decodePublicKey(s) {
  var split = s.split(" ");
  var prefix = split[0];
  if (prefix !== "ssh-rsa") {
    throw new Error("Unknown prefix: " + prefix);
  }
  var buffer = pemToArray(split[1]);
  var nameLen = arrayToLen(buffer.splice(0, 4));
  var type = arrayToString(buffer.splice(0, nameLen));
  if (type !== "ssh-rsa") {
    throw new Error("Unknown key type: " + type);
  }
  var exponentLen = arrayToLen(buffer.splice(0, 4));
  var exponent = buffer.splice(0, exponentLen);
  var keyLen = arrayToLen(buffer.splice(0, 4));
  var key = buffer.splice(0, keyLen);
  return { type: type, exponent: exponent, key: key, name: split[2] };
}

function checkHighestBit(v) {
  if (v[0] >> 7 === 1) {
    // add leading zero if first bit is set
    v.unshift(0);
  }
  return v;
}

function jwkToInternal(jwk) {
  return {
    type: "ssh-rsa",
    exponent: checkHighestBit(stringToArray(base64urlDecode(jwk.e))),
    name: "name",
    key: checkHighestBit(stringToArray(base64urlDecode(jwk.n)))
  };
}

function encodePublicKey(jwk, name) {
  var k = jwkToInternal(jwk);
  k.name = name;
  var keyLenA = lenToArray(k.key.length);
  var exponentLenA = lenToArray(k.exponent.length);
  var typeLenA = lenToArray(k.type.length);
  var array = [].concat(typeLenA, stringToArray(k.type), exponentLenA, k.exponent, keyLenA, k.key);
  var encoding = arrayToPem(array);
  return k.type + " " + encoding + " " + k.name;
}

function asnEncodeLen(n) {
  var result = [];
  if (n >> 7) {
    result = integerToOctet(n);
    result.unshift(0x80 + result.length);
  } else {
    result.push(n);
  }
  return result;
}

function encodePrivateKey(jwk) {
  var _seq;

  var order = ["n", "e", "d", "p", "q", "dp", "dq", "qi"];
  var list = order.map(function (prop) {
    var v = checkHighestBit(stringToArray(base64urlDecode(jwk[prop])));
    var len = asnEncodeLen(v.length);
    return [0x02].concat(len, v); // int tag is 0x02
  });
  var seq = [0x02, 0x01, 0x00]; // extra seq for SSH
  seq = (_seq = seq).concat.apply(_seq, _toConsumableArray(list));
  var len = asnEncodeLen(seq.length);
  var a = [0x30].concat(len, seq); // seq is 0x30
  return arrayToPem(a);
}

_module.exports = { base64urlToArray: base64urlToArray, decodePublicKey: decodePublicKey, encodePublicKey: encodePublicKey, encodePrivateKey: encodePrivateKey };
/* global encodePrivateKey, encodePublicKey */
var extractable = true;

function wrap(text, len) {
  var length = len || 72;
  var result = "";
  for (var i = 0; i < text.length; i += length) {
    result += text.slice(i, i + length);
    result += "\n";
  }
  return result;
}

function rsaPrivateKey(key) {
  return "-----BEGIN RSA PRIVATE KEY-----\n" + key + "-----END RSA PRIVATE KEY-----";
}

function arrayBufferToBase64(buffer) {
  var binary = "";
  var bytes = new Uint8Array(buffer);
  var len = bytes.byteLength;
  for (var i = 0; i < len; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function generateKeyPair(alg, size, name) {
  return window.crypto.subtle.generateKey({
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048, // can be 1024, 2048, or 4096
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: { name: "SHA-1" } // can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
  }, extractable, ["sign", "verify"]).then(function (key) {
    var privateKey = window.crypto.subtle.exportKey("jwk", key.privateKey).then(encodePrivateKey).then(wrap).then(rsaPrivateKey);

    var publicKey = window.crypto.subtle.exportKey("jwk", key.publicKey).then(function (jwk) {
      return encodePublicKey(jwk, name);
    });
    return Promise.all([privateKey, publicKey]);
  });
}

window.keygen = { arrayBufferToBase64: arrayBufferToBase64, generateKeyPair: generateKeyPair };
}(window));
