import assert from "assert";
import { ECIES, simpECIES } from "./src/main";

function testBasicEncryptionDecryption() {
    const ecies = new ECIES();
    const recipientKeyPair = ecies.generateKeyPair();
    const privateKey = recipientKeyPair.getPrivateKey();
    const publicKey = recipientKeyPair.getPublicKey();
    const message = Buffer.from("This is a secret message.");

    const encryptedData = ecies.encrypt(publicKey, message);
    const decryptedMessage = ecies.decrypt(privateKey, encryptedData);

    assert.deepStrictEqual(decryptedMessage, message, "Decrypted message does not match the original message");
}

function testSimpEncryptionDecryption() {
    const simpEcies = new simpECIES('SM2');
    const recipientKeyPair = simpEcies.generateKeyPair();
    const privateKey = recipientKeyPair.getPrivateKey();
    const publicKey = recipientKeyPair.getPublicKey();
    const message = Buffer.from("This is a secret message.");

    const encryptedData = simpEcies.encrypt(publicKey, message);
    const decryptedMessage = simpEcies.decrypt(privateKey, encryptedData);

    assert.deepStrictEqual(decryptedMessage, message, "Decrypted message does not match the original message");
}

testBasicEncryptionDecryption();

testSimpEncryptionDecryption();

console.log("All tests passed.");
