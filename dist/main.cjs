"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/main.ts
var main_exports = {};
__export(main_exports, {
  encrypt: () => encrypt,
  generateKeyPair: () => generateKeyPair
});
module.exports = __toCommonJS(main_exports);
var crypto = __toESM(require("crypto"), 1);
function generateKeyPair(curveName = "secp256k1") {
  const sk2 = crypto.createECDH(curveName);
  sk2.generateKeys();
  return sk2;
}
__name(generateKeyPair, "generateKeyPair");
function aecEnc(msg, aesKey, iv) {
  const cipher = crypto.createCipheriv("chacha20-poly1305", aesKey, iv);
  const ciphertext = cipher.update(msg);
  cipher.final();
  return ciphertext;
}
__name(aecEnc, "aecEnc");
async function encrypt(pubKey, message) {
  const ephemKeyPair = generateKeyPair();
  const ephemPublicKey = ephemKeyPair.getPublicKey();
  const shareKey = ephemKeyPair.computeSecret(pubKey);
  console.log(`sharekey: ${shareKey.byteLength}`, shareKey);
  const hash = await crypto.subtle.digest("SHA-256", shareKey);
  const encKey = Buffer.from(hash.slice(0, 32));
  const iv = crypto.randomBytes(16);
  const data = aecEnc(message, encKey, iv);
  const ciphertext = data;
  console.log(ciphertext);
  return Buffer.concat([shareKey, ciphertext]);
}
__name(encrypt, "encrypt");
var sk = generateKeyPair();
console.log(sk.getPublicKey().byteLength, sk.getPublicKey("base64"));
console.log(encrypt(sk.getPublicKey(), Buffer.from("Hello, World")));
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  encrypt,
  generateKeyPair
});
