var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/main.ts
import * as crypto from "crypto";
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
export {
  encrypt,
  generateKeyPair
};
