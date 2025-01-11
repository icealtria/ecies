import * as crypto from 'crypto';
import { getCurves } from 'crypto';

type CurveName = ReturnType<typeof getCurves>[number];

interface Ecies {
    iv: Buffer;
    ephemPublicKey: Buffer;
    ciphertext: Buffer;
    mac: Buffer;
}
declare function generateKeyPair(curveName?: CurveName): crypto.ECDH;
declare function encrypt(pubKey: Buffer, message: Buffer): Promise<Buffer>;

export { type Ecies, encrypt, generateKeyPair };
