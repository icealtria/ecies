import * as crypto from "crypto";
import { type CurveName } from './type';

const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const ALGORITHM = 'chacha20-poly1305';

export class ECIES {
    private readonly curveName: CurveName;

    constructor(curveName: CurveName = 'prime256v1') {
        this.curveName = curveName;
    }

    public generateKeyPair(): crypto.ECDH {
        const keyPair = crypto.createECDH(this.curveName);
        keyPair.generateKeys();
        return keyPair;
    }

    private deriveKeys(sharedSecret: Buffer, salt: Buffer): Buffer {
        const info = Buffer.alloc(0);
        const derivedKey = crypto.hkdfSync('sha256', sharedSecret, salt, info, KEY_LENGTH);
        return Buffer.from(derivedKey);
    }

    public encrypt(recipientPublicKey: Buffer, message: Buffer): Buffer {
        try {
            const ephemeralKeyPair = this.generateKeyPair();
            const ephemeralPublicKey = ephemeralKeyPair.getPublicKey();
            const sharedSecret = ephemeralKeyPair.computeSecret(recipientPublicKey);
            const encryptionKey = this.deriveKeys(sharedSecret, ephemeralPublicKey);

            const iv = crypto.randomBytes(IV_LENGTH);
            const cipher = crypto.createCipheriv(
                ALGORITHM,
                encryptionKey,
                iv,
                { authTagLength: AUTH_TAG_LENGTH }
            );

            cipher.setAAD(ephemeralPublicKey, { plaintextLength: message.length });
            const ciphertext = Buffer.concat([
                cipher.update(message),
                cipher.final()
            ]);
            const authTag = cipher.getAuthTag();

            return Buffer.concat([
                ephemeralPublicKey,
                iv,
                ciphertext,
                authTag
            ]);
        } catch (error) {
            console.error("Encryption Error:", error);
            throw new Error("Failed to encrypt message");
        }
    }

    public decrypt(privateKey: Buffer, encryptedData: Buffer): Buffer {
        try {
            const ecdh = crypto.createECDH(this.curveName);
            ecdh.setPrivateKey(privateKey);

            let offset = 0;
            const ephemPubKeyLength = ecdh.getPublicKey().length;
            const ephemeralPublicKey = encryptedData.subarray(offset, offset + ephemPubKeyLength);
            offset += ephemPubKeyLength;

            const iv = encryptedData.subarray(offset, offset + IV_LENGTH);
            offset += IV_LENGTH;

            const authTag = encryptedData.subarray(-AUTH_TAG_LENGTH);
            const ciphertext = encryptedData.subarray(offset, -AUTH_TAG_LENGTH);

            const sharedSecret = ecdh.computeSecret(ephemeralPublicKey);
            const encryptionKey = this.deriveKeys(sharedSecret, ephemeralPublicKey);

            const decipher = crypto.createDecipheriv(
                ALGORITHM,
                encryptionKey,
                iv,
                { authTagLength: AUTH_TAG_LENGTH }
            );

            decipher.setAAD(ephemeralPublicKey, { plaintextLength: ciphertext.length });
            decipher.setAuthTag(authTag);

            return Buffer.concat([
                decipher.update(ciphertext),
                decipher.final()
            ]);
        } catch (error) {
            console.error("Decryption Error:", error);
            throw new Error("Failed to decrypt message");
        }
    }
}
