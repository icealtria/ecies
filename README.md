# ECIES

⚠️ **SECURITY WARNING** ⚠️

This is an **experimental** implementation that has NOT undergone professional security audit. It is NOT recommended for production use or any application requiring guaranteed security. Use at your own risk.

A lightweight TypeScript implementation of Elliptic Curve Integrated Encryption Scheme (ECIES) using Node.js's built-in `crypto` module.

## Features

- Pure TypeScript implementation
- Uses Node.js built-in `crypto` module
- Zero external crypto dependencies
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
// or 
// import { simpECIES } from '@icealtria/ecies';

// Initialize ECIES
const ecies = new ECIES();

// Generate key pair
const keyPair = ecies.generateKeyPair();
const privateKey = keyPair.getPrivateKey();
const publicKey = keyPair.getPublicKey();

// Encrypt message
const message = Buffer.from("This is a secret message.");
const encryptedData = ecies.encrypt(publicKey, message);

// Decrypt message
const decryptedMessage = ecies.decrypt(privateKey, encryptedData);
console.log(decryptedMessage.toString());
// This is a secret message.
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
