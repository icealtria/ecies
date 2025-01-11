import * as crypto from "crypto";

const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const MAC_KEY_LENGTH = 32;
const MAC_LENGTH = 32;
const AUTH_TAG_LENGTH = 16;
const ALGORITHM = 'chacha20-poly1305';

export class ECIES {
    private readonly curveName: string;

    constructor(curveName: string = 'prime256v1') {
        this.curveName = curveName;
    }

    public generateKeyPair(): crypto.ECDH {
        const keyPair = crypto.createECDH(this.curveName);
        keyPair.generateKeys();
        return keyPair;
    }

    private deriveKeys(sharedSecret: Buffer) {
        const kdfOutput = this.kdf(sharedSecret);

        return {
            encryptionKey: kdfOutput.subarray(0, KEY_LENGTH),
            macKey: kdfOutput.subarray(KEY_LENGTH, KEY_LENGTH + MAC_KEY_LENGTH),
        };
    }

    private kdf(secret: Buffer): Buffer {
        const counter = Buffer.alloc(4);
        counter.writeUInt32BE(1, 0);

        const input = Buffer.concat([
            secret,
            counter,
        ]);

        return crypto.createHash('sha256').update(input).digest();
    }

    private computeMAC(macKey: Buffer, ciphertext: Buffer): Buffer {
        const hmac = crypto.createHmac('sha256', macKey);
        hmac.update(ciphertext);
        return hmac.digest();
    }

    public encrypt(
        recipientPublicKey: Buffer,
        message: Buffer
    ): Buffer {
        try {
            const ephemeralKeyPair = this.generateKeyPair();
            const ephemeralPublicKey = ephemeralKeyPair.getPublicKey();

            const sharedSecret = ephemeralKeyPair.computeSecret(recipientPublicKey);

            const { encryptionKey, macKey } = this.deriveKeys(sharedSecret);

            const iv = crypto.randomBytes(IV_LENGTH);

            const cipher = crypto.createCipheriv(ALGORITHM, encryptionKey, iv, { authTagLength: AUTH_TAG_LENGTH });
            const ciphertext = Buffer.concat([
                cipher.update(message),
                cipher.final()
            ]);
            const authTag = cipher.getAuthTag();

            const mac = this.computeMAC(macKey, Buffer.concat([ciphertext, authTag]));

            return Buffer.concat([
                ephemeralPublicKey,
                iv,
                ciphertext,
                authTag,
                mac
            ]);
        } catch (error) {
            console.error("Encryption Error:", error);
            throw new Error("Failed to encrypt message");
        }
    }

    public decrypt(
        privateKey: Buffer,
        encryptedData: Buffer
    ): Buffer {
        try {
            const ecdh = crypto.createECDH(this.curveName);
            ecdh.setPrivateKey(privateKey);

            let offset = 0;
            const ephemPubKeyLength = ecdh.getPublicKey().length;
            const ephemeralPublicKey = encryptedData.subarray(offset, ephemPubKeyLength);
            offset += ephemPubKeyLength;

            const iv = encryptedData.subarray(offset, offset + IV_LENGTH);
            offset += IV_LENGTH;

            const mac = encryptedData.subarray(-MAC_LENGTH);
            const authTag = encryptedData.subarray(-MAC_LENGTH - AUTH_TAG_LENGTH, -MAC_LENGTH);
            const ciphertext = encryptedData.subarray(offset, -MAC_LENGTH - AUTH_TAG_LENGTH);

            const sharedSecret = ecdh.computeSecret(ephemeralPublicKey);

            const { encryptionKey, macKey } = this.deriveKeys(sharedSecret);

            const computedMac = this.computeMAC(macKey, Buffer.concat([ciphertext, authTag]));
            if (!crypto.timingSafeEqual(computedMac, mac)) {
                throw new Error('Invalid MAC');
            }

            const decipher = crypto.createDecipheriv(ALGORITHM, encryptionKey, iv, { authTagLength: AUTH_TAG_LENGTH });
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
