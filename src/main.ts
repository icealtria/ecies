import * as crypto from "node:crypto";

// Constants for key derivation and MAC
const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const MAC_KEY_LENGTH = 32;
const MAC_LENGTH = 32;
const AUTH_TAG_LENGTH = 16;
const ALGORITHM = 'chacha20-poly1305';

interface ECIESKeys {
  encryptionKey: Buffer;
  macKey: Buffer;
}

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

  private deriveKeys(sharedSecret: Buffer, s1?: Buffer): ECIESKeys {
    // KDF implementation following ANSI-X9.63-KDF with SHA-256
    const kdfOutput = this.kdf(sharedSecret, s1);

    return {
      encryptionKey: kdfOutput.subarray(0, KEY_LENGTH),
      macKey: kdfOutput.subarray(KEY_LENGTH, KEY_LENGTH + MAC_KEY_LENGTH),
    };
  }

  private kdf(secret: Buffer, s1?: Buffer): Buffer {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(1, 0);

    const input = Buffer.concat([
      secret,
      counter,
      s1 || Buffer.alloc(0)
    ]);

    return crypto.createHash('sha256').update(input).digest();
  }

  private computeMAC(macKey: Buffer, ciphertext: Buffer, s2?: Buffer): Buffer {
    const hmac = crypto.createHmac('sha256', macKey);
    hmac.update(ciphertext);
    if (s2) {
      hmac.update(s2);
    }
    return hmac.digest();
  }

  public async encrypt(
    recipientPublicKey: Buffer,
    message: Buffer,
    s1?: Buffer,
    s2?: Buffer
  ): Promise<Buffer> {
    try {
      // 1. Generate ephemeral key pair
      const ephemeralKeyPair = this.generateKeyPair();
      const ephemeralPublicKey = ephemeralKeyPair.getPublicKey();

      // 2. Derive shared secret
      const sharedSecret = ephemeralKeyPair.computeSecret(recipientPublicKey);

      // 3. Derive encryption and MAC keys
      const { encryptionKey, macKey } = this.deriveKeys(sharedSecret, s1);

      // Generate a random IV (12 bytes for AES-GCM)
      const iv = crypto.randomBytes(IV_LENGTH);

      // 4. Encrypt message
      const cipher = crypto.createCipheriv(ALGORITHM, encryptionKey, iv, { authTagLength: AUTH_TAG_LENGTH });
      const ciphertext = Buffer.concat([
        cipher.update(message),
        cipher.final()
      ]);
      const authTag = cipher.getAuthTag();

      // 5. Compute MAC
      const mac = this.computeMAC(macKey, Buffer.concat([ciphertext, authTag]), s2);

      // 6. Format output
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

  public async decrypt(
    privateKey: Buffer,
    encryptedData: Buffer,
    s1?: Buffer,
    s2?: Buffer
  ): Promise<Buffer> {
    try {
      const ecdh = crypto.createECDH(this.curveName);
      ecdh.setPrivateKey(privateKey);

      // Parse encrypted data
      let offset = 0;
      const ephemPubKeyLength = ecdh.getPublicKey().length;
      const ephemeralPublicKey = encryptedData.subarray(offset, ephemPubKeyLength);
      offset += ephemPubKeyLength;

      const iv = encryptedData.subarray(offset, offset + IV_LENGTH);
      offset += IV_LENGTH;

      const mac = encryptedData.subarray(-MAC_LENGTH);
      const authTag = encryptedData.subarray(-MAC_LENGTH - AUTH_TAG_LENGTH, -MAC_LENGTH);
      const ciphertext = encryptedData.subarray(offset, -MAC_LENGTH - AUTH_TAG_LENGTH);

      // 1. Derive shared secret
      const sharedSecret = ecdh.computeSecret(ephemeralPublicKey);

      // 2. Derive keys
      const { encryptionKey, macKey } = this.deriveKeys(sharedSecret, s1);

      // 3. Verify MAC
      const computedMac = this.computeMAC(macKey, Buffer.concat([ciphertext, authTag]), s2);
      if (!crypto.timingSafeEqual(computedMac, mac)) {
        throw new Error('Invalid MAC');
      }

      // 4. Decrypt message
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

// Example usage
async function example() {
  try {
    const ecies = new ECIES();

    // Generate key pair for recipient
    const recipientKeyPair = ecies.generateKeyPair();

    // Encrypt a message
    const message = Buffer.from('maomao@gmail.com');
    const encrypted = await ecies.encrypt(
      recipientKeyPair.getPublicKey(),
      message
    );

    console.log('Encrypted message (base64):', encrypted.toString('base64'));

    // Decrypt the message
    const decrypted = await ecies.decrypt(
      recipientKeyPair.getPrivateKey(),
      encrypted
    );

    console.log('Original message:', message.toString('utf-8'));
    console.log('Decrypted message:', decrypted.toString('utf-8'));
  } catch (error) {
    console.error('Example Error:', error);
  }
}

example();