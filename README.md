# ECIES

A lightweight TypeScript implementation of Elliptic Curve Integrated Encryption Scheme (ECIES) using Node.js's built-in `crypto` module.

## Features

- Pure TypeScript implementation
- Uses Node.js built-in `crypto` module
- Zero external dependencies
- Two implementations available:
  - Standard ECIES: Full implementation with all security features
  - Simplified ECIES: Minimalist implementation for smaller ciphertext size

## Installation

```bash
pnpm install ecies
```

## Usage

```typescript
import { ECIES } from '@icealtria/ecies';

const ecies = new ECIES();

// Generate key pair
const keyPair = ecies.generateKeyPair();
const privateKey = keyPair.getPrivateKey();
const publicKey = keyPair.getPublicKey();

// Encrypt message
const message = Buffer.from("Hello world! 🌏");
const encryptedData = ecies.encrypt(publicKey, message);

console.log(encryptedData.toString('base64'))
// BIexVy5zciKoxoo5w/8Caa/PJPuzWBiU9WrtY9f5x0PwyjXigfmklwqGwqUH7k7P5KlBOs5hCoMHc/vMOZtyyDG8yPx2djfPpgQ+5kpUdmtNCl+y82mCNoGAFpP7vrTcv14I8bqhbahXGGKNFPto0QnEqGOtMxm69JNm+N1BDkwMrhTFy9txXnL9fHyMYQ==

// Decrypt message
const decryptedMessage = ecies.decrypt(privateKey, encryptedData);
console.log(decryptedMessage.toString());
// Hello World! 🌍
```

## Implementation Details

### Standard ECIES
Standard implementation with complete security features.

### Simplified ECIES
`simpECIES` is a minimalist implementation optimized for smaller ciphertext size. Note: this trades some security features for size reduction.

## API Reference

### ECIES Class

- `generateKeyPair()`: Generates a new key pair
- `encrypt(publicKey, message)`: Encrypts a message using recipient's public key
- `decrypt(privateKey, encryptedData)`: Decrypts message using recipient's private key

### simpECIES Class

- `generateKeyPair()`: Generates a new key pair
- `encrypt(publicKey, message)`: Encrypts a message using recipient's public key
- `decrypt(privateKey, encryptedData)`: Decrypts message using recipient's private key

## License

MIT
