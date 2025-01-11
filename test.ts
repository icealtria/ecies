import { ECIES } from "./src/main";

import * as assert from 'assert';

// Test case 1: Basic encryption and decryption test
function testBasicEncryptionDecryption() {
    const ecies = new ECIES();

    // Generate key pairs
    const recipientKeyPair = ecies.generateKeyPair();
    const privateKey = recipientKeyPair.getPrivateKey();
    const publicKey = recipientKeyPair.getPublicKey();

    // Sample message to encrypt
    const message = Buffer.from("This is a secret message.");

    // Encrypt message
    const encryptedData = ecies.encrypt(publicKey, message);

    // Decrypt message
    const decryptedMessage = ecies.decrypt(privateKey, encryptedData);

    // Verify that the decrypted message matches the original message
    assert.deepStrictEqual(decryptedMessage, message, "Decrypted message does not match the original message");
}


testBasicEncryptionDecryption();

console.log("All tests passed.");
