// adapted from https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-08#appendix-C

function base64urlEncode(arg) {
  const step1 = window.btoa(arg); // Regular base64 encoder
  const step2 = step1.split("=")[0]; // Remove any trailing '='s
  const step3 = step2.replace(/\+/g, "-"); // 62nd char of encoding
  const step4 = step3.replace(/\//g, "_"); // 63rd char of encoding
  return step4;
}

function base64urlDecode(s) {
  const step1 = s.replace(/-/g, "+"); // 62nd char of encoding
  const step2 = step1.replace(/_/g, "/"); // 63rd char of encoding
  let step3 = step2;
  switch (step2.length % 4) { // Pad with trailing '='s
    case 0: // No pad chars in this case
      break;
    case 2: // Two pad chars
      step3 += "==";
      break;
    case 3: // One pad char
      step3 += "=";
      break;
    default:
      throw new Error("Illegal base64url string!");
  }
  return window.atob(step3); // Regular base64 decoder
}

const module = window.module || {};
module.exports = { base64urlDecode, base64urlEncode };
/* eslint no-bitwise: 0 */
/* global base64urlDecode */

function arrayToString(a) {
  return String.fromCharCode.apply(null, a);
}

function stringToArray(s) {
  return s.split("").map(c => c.charCodeAt());
}

function base64urlToArray(s) {
  return stringToArray(base64urlDecode(s));
}

function pemToArray(pem) {
  return stringToArray(window.atob(pem));
}

function arrayToPem(a) {
  return window.btoa(a.map(c => String.fromCharCode(c)).join(""));
}

function arrayToLen(a) {
  let result = 0;
  for (let i = 0; i < a.length; i += 1) {
    result = result * 256 + a[i];
  }
  return result;
}

function integerToOctet(n) {
  const result = [];
  for (let i = n; i > 0; i >>= 8) {
    result.push(i & 0xff);
  }
  return result.reverse();
}

function lenToArray(n) {
  const oct = integerToOctet(n);
  let i;
  for (i = oct.length; i < 4; i += 1) {
    oct.unshift(0);
  }
  return oct;
}

function decodePublicKey(s) {
  const split = s.split(" ");
  const prefix = split[0];
  if (prefix !== "ssh-rsa") {
    throw new Error(`Unknown prefix: ${prefix}`);
  }
  const buffer = pemToArray(split[1]);
  const nameLen = arrayToLen(buffer.splice(0, 4));
  const type = arrayToString(buffer.splice(0, nameLen));
  if (type !== "ssh-rsa") {
    throw new Error(`Unknown key type: ${type}`);
  }
  const exponentLen = arrayToLen(buffer.splice(0, 4));
  const exponent = buffer.splice(0, exponentLen);
  const keyLen = arrayToLen(buffer.splice(0, 4));
  const key = buffer.splice(0, keyLen);
  return { type, exponent, key, name: split[2] };
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
    key: checkHighestBit(stringToArray(base64urlDecode(jwk.n))),
  };
}

function encodePublicKey(jwk, name) {
  const k = jwkToInternal(jwk);
  k.name = name;
  const keyLenA = lenToArray(k.key.length);
  const exponentLenA = lenToArray(k.exponent.length);
  const typeLenA = lenToArray(k.type.length);
  const array = [].concat(typeLenA, stringToArray(k.type), exponentLenA, k.exponent, keyLenA, k.key);
  const encoding = arrayToPem(array);
  return `${k.type} ${encoding} ${k.name}`;
}

function asnEncodeLen(n) {
  let result = [];
  if (n >> 7) {
    result = integerToOctet(n);
    result.unshift(0x80 + result.length);
  } else {
    result.push(n);
  }
  return result;
}

function encodePrivateKey(jwk) {
  const order = ["n", "e", "d", "p", "q", "dp", "dq", "qi"];
  const list = order.map(prop => {
    const v = checkHighestBit(stringToArray(base64urlDecode(jwk[prop])));
    const len = asnEncodeLen(v.length);
    return [0x02].concat(len, v); // int tag is 0x02
  });
  let seq = [0x02, 0x01, 0x00]; // extra seq for SSH
  seq = seq.concat(...list);
  const len = asnEncodeLen(seq.length);
  const a = [0x30].concat(len, seq); // seq is 0x30
  return arrayToPem(a);
}

module.exports = { base64urlToArray, decodePublicKey, encodePublicKey, encodePrivateKey };
/* global encodePrivateKey, encodePublicKey */
const extractable = true;

function wrap(text, len) {
  const length = len || 72;
  let result = "";
  for (let i = 0; i < text.length; i += length) {
    result += text.slice(i, i + length);
    result += "\n";
  }
  return result;
}

function rsaPrivateKey(key) {
  return `-----BEGIN RSA PRIVATE KEY-----\n${key}-----END RSA PRIVATE KEY-----`;
}

function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function generateKeyPair(alg, size, name) {
  return window.crypto.subtle
    .generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048, // can be 1024, 2048, or 4096
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-1" }, // can be "SHA-1", "SHA-256", "SHA-384", or "SHA-512"
      },
      extractable,
      ["sign", "verify"]
    )
    .then(key => {
      const privateKey = window.crypto.subtle
        .exportKey("jwk", key.privateKey)
        .then(encodePrivateKey)
        .then(wrap)
        .then(rsaPrivateKey);

      const publicKey = window.crypto.subtle.exportKey("jwk", key.publicKey).then(jwk => encodePublicKey(jwk, name));
      return Promise.all([privateKey, publicKey]);
    });
}

module.exports = { arrayBufferToBase64, generateKeyPair };
