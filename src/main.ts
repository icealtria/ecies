import * as crypto from "crypto";
import { CurveName } from "./types.ts";

export function generateKeyPair(curveName: CurveName = 'prime256v1') {
    const sk = crypto.createECDH(curveName);
    sk.generateKeys();
    return sk
}


export async function encrypt(pubKey: Buffer, message: Buffer, curveName: CurveName = 'prime256v1'): Promise<Buffer> {
    const ephemKeyPair = generateKeyPair(curveName);
    const ephemPublicKey = ephemKeyPair.getPublicKey();
    const shareKey = ephemKeyPair.computeSecret(pubKey);

    const hash = crypto.createHash('sha256').update(shareKey).digest();

    const encKey = hash.subarray(0, 32);
    const iv = hash.subarray(32 - 12);

    const ciphertext = aecEnc(message, encKey, iv);

    return Buffer.concat([ephemPublicKey, ciphertext]);
}

export function decrypt(privKey: Buffer, encryptedData: Buffer, curveName: CurveName = 'prime256v1'): Buffer {
    const ecdh = crypto.createECDH(curveName);
    ecdh.setPrivateKey(privKey);

    const byteLength = ecdh.getPublicKey().byteLength

    console.log(byteLength)

    const ephemPublicKey = encryptedData.subarray(0, byteLength);
    const ciphertext = encryptedData.subarray(byteLength);


    const sharedKey = ecdh.computeSecret(ephemPublicKey);

    const hash = crypto.createHash('sha256').update(sharedKey).digest();
    const encKey = hash.subarray(0, 32);
    const iv = hash.subarray(32 - 12);

    const message = aesDec(ciphertext, encKey, iv);
    return message;
}

function aesDec(msg: Buffer, aesKey: Buffer, iv: Buffer) {
    const decipher = crypto.createDecipheriv('chacha20-poly1305', aesKey, iv);
    const recText = decipher.update(msg)

    try {
        decipher.final
    } catch (err) {
        console.log(err)
    }
    return recText
}

function aecEnc(msg: Buffer, aesKey: Buffer, iv: Buffer) {
    const cipher = crypto.createCipheriv('chacha20-poly1305', aesKey, iv);
    const ciphertext = Buffer.concat([cipher.update(msg), cipher.final()]);
    return ciphertext;
}

const sk = generateKeyPair();

console.log(sk.getPublicKey().byteLength)

const encrypted = (await encrypt(sk.getPublicKey(), Buffer.from('maomao@gmail.com'))).toString('base64')

console.log(encrypted)

const decrypted = decrypt(sk.getPrivateKey(), Buffer.from(encrypted, 'base64'));

console.log(decrypted.toString('utf-8'))
