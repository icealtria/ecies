import assert from "assert";
import * as crypto from "crypto";
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
    const simpEcies = new simpECIES('brainpoolP160r1');
    const recipientKeyPair = simpEcies.generateKeyPair();
    const privateKey = recipientKeyPair.getPrivateKey();
    const publicKey = recipientKeyPair.getPublicKey();
    const message = Buffer.from("This is a secret message.");

    const encryptedData = simpEcies.encrypt(publicKey, message);
    const decryptedMessage = simpEcies.decrypt(privateKey, encryptedData);

    assert.deepStrictEqual(decryptedMessage, message, "Decrypted message does not match the original message");
}

function testEmptyMessage() {
    const ecies = new ECIES();
    const recipientKeyPair = ecies.generateKeyPair();
    const privateKey = recipientKeyPair.getPrivateKey();
    const publicKey = recipientKeyPair.getPublicKey();
    const message = Buffer.from("");

    const encryptedData = ecies.encrypt(publicKey, message);
    const decryptedMessage = ecies.decrypt(privateKey, encryptedData);

    assert.deepStrictEqual(decryptedMessage, message, "Empty message decryption failed");
}


function testDifferentCurves() {
    const curves = crypto.getCurves();
    curves.forEach((curve) => {
        const Ecies = new ECIES(curve);
        const recipientKeyPair = Ecies.generateKeyPair();
        const privateKey = recipientKeyPair.getPrivateKey();
        const publicKey = recipientKeyPair.getPublicKey();
        const message = Buffer.from(`Test message with curve ${curve}`);

        const encryptedData = Ecies.encrypt(publicKey, message);
        const decryptedMessage = Ecies.decrypt(privateKey, encryptedData);

        assert.deepStrictEqual(decryptedMessage, message, `Decryption failed with curve ${curve}`);
    });
}
function testPerformance() {
    const ecies = new simpECIES();
    const recipientKeyPair = ecies.generateKeyPair();
    const privateKey = recipientKeyPair.getPrivateKey();
    const publicKey = recipientKeyPair.getPublicKey();
    const message = Buffer.alloc(1024 * 1024, "A");

    console.time("Encryption Time");
    const encryptedData = ecies.encrypt(publicKey, message);
    console.timeEnd("Encryption Time");

    console.time("Decryption Time");
    const decryptedMessage = ecies.decrypt(privateKey, encryptedData);
    console.timeEnd("Decryption Time");

    assert.deepStrictEqual(decryptedMessage, message, "Performance test decryption failed");
}

function runAllTests() {
    testBasicEncryptionDecryption();
    testSimpEncryptionDecryption();
    testEmptyMessage();
    testDifferentCurves();
    testPerformance();

    console.log("All tests passed.");
}

runAllTests();
