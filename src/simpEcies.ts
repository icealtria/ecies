import * as crypto from "crypto";
import { type CurveName } from './type';

const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 8;
const ALGORITHM = 'chacha20-poly1305';

export class simpECIES {
    private readonly curveName: CurveName;

    constructor(curveName: CurveName = 'prime256v1') {
        this.curveName = curveName;
    }

    public generateKeyPair(): crypto.ECDH {
        const keyPair = crypto.createECDH(this.curveName);
        keyPair.generateKeys();
        return keyPair;
    }

    private deriveKeys(sharedSecret: Buffer) {
        const hash = crypto.createHash('sha256')
            .update(sharedSecret)
            .digest();

        return {
            encryptionKey: hash.subarray(0, KEY_LENGTH),
            iv: hash.subarray(-IV_LENGTH),
        };
    }

    public encrypt(recipientPublicKey: Buffer, message: Buffer): Buffer {
        try {
            const ephemeralKeyPair = this.generateKeyPair();
            const ephemeralPublicKey = ephemeralKeyPair.getPublicKey();
            const sharedSecret = ephemeralKeyPair.computeSecret(recipientPublicKey);

            const { encryptionKey, iv } = this.deriveKeys(sharedSecret);

            const cipher = crypto.createCipheriv(
                ALGORITHM,
                encryptionKey,
                iv,
                { authTagLength: AUTH_TAG_LENGTH }
            );

            const ciphertext = Buffer.concat([
                cipher.update(message),
                cipher.final()
            ]);
            const authTag = cipher.getAuthTag();

            return Buffer.concat([
                ephemeralPublicKey,
                authTag,
                ciphertext
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

            let offset = ecdh.getPublicKey().byteLength;
            const ephemeralPublicKey = encryptedData.subarray(0, offset);
            const authTag = encryptedData.subarray(offset, offset + AUTH_TAG_LENGTH);
            const ciphertext = encryptedData.subarray(offset + AUTH_TAG_LENGTH);

            const sharedSecret = ecdh.computeSecret(ephemeralPublicKey);
            const { encryptionKey, iv } = this.deriveKeys(sharedSecret);

            const decipher = crypto.createDecipheriv(
                ALGORITHM,
                encryptionKey,
                iv,
                { authTagLength: AUTH_TAG_LENGTH }
            );
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
