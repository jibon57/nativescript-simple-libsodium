import { Observable } from 'tns-core-modules/data/observable';
export declare class Common extends Observable {
  constructor();
}
export declare const enum AEDMethod {
  CHACHA20_POLY1305 = 0,
  CHACHA20_POLY1305_IETF = 1,
  XCHACHA20_POLY1305_IETF = 2,
  AES256GCM = 3,
}
export declare const enum AEDValues {
  CHACHA20POLY1305_KEYBYTES = 32,
  CHACHA20POLY1305_NPUBBYTES = 8,
  CHACHA20POLY1305_ABYTES = 16,
  CHACHA20POLY1305_IETF_ABYTES = 16,
  CHACHA20POLY1305_IETF_KEYBYTES = 32,
  CHACHA20POLY1305_IETF_NPUBBYTES = 12,
  XCHACHA20POLY1305_IETF_KEYBYTES = 32,
  XCHACHA20POLY1305_IETF_ABYTES = 16,
  XCHACHA20POLY1305_IETF_NPUBBYTES = 24,
  AES256GCM_KEYBYTES = 32,
  AES256GCM_NSECBYTES = 0,
  AES256GCM_NPUBBYTES = 12,
  AES256GCM_ABYTES = 16,
}

export declare const enum Base64Variant {
  sodium_base64_VARIANT_ORIGINAL = 1,
  sodium_base64_VARIANT_ORIGINAL_NO_PADDING = 3,
  sodium_base64_VARIANT_URLSAFE = 5,
  sodium_base64_VARIANT_URLSAFE_NO_PADDING = 7,
}

export declare const enum Keybytes {
  SECRETBOX_KEYBYTES = 32,
  STREAM_KEYBYTES = 32,
  PWHASH_SALTBYTES = 16
}

export declare const enum Noncebytes {
  SECRETBOX_NONCEBYTES = 24,
  STREAM_NONCEBYTES = 24,
  BOX_NONCEBYTES = 24
}

export declare class SimpleLibsodium extends Common {

  sodium;
  lazySodium;
  constructor();

  generateRandomData(length?: number): {
    'hexString': string;
    'raw': any;
  };
  generateKeyWithSuppliedString(mykey: string, length?: number, salt?: any, opslimit?: number, memlimit?: number): {
    'hexString': string;
    'raw': any;
    'saltHexString': string;
    'rawSalt': any;
  };
  AEDEncrypt(method: AEDMethod, msg: string, key: any, nonce?: any, additionalMsg?: string): {
    'status': boolean;
    'CryptedHexString': string;
    'rawCrypted': any;
    'nonceHexString': string;
    'rawNonce': any;
  };
  AEDDecrypt(method: AEDMethod, encrypData: any, key: any, nonce: any, additionalMsg?: string): {
    'string': string;
    'raw': any;
  };
  secretBoxEncrypt(text: string, key: any, nonce?: any): {
    'CryptedHexString': string;
    'rawCrypted': any;
    'nonceHexString': string;
    'rawNonce': any;
  };
  secretBoxOpen(encrypData: any, key: any, nonce: any): {
    'string': string;
    'raw': any;
  };
  xSalsa20Encrypt(message: string, key: any, nonce?: any): {
    'status': boolean;
    'CryptedHexString': string;
    'rawCrypted': any;
    'NonceHexString': string;
    'rawNonce': any;
    'msg'?: string;
  };
  xSalsa20Decrypt(encrypData: any, key: any, nonce: any): {
    'string': string;
    'raw': any;
  };
  boxEasy(msg: string, public_key: any, private_key: any, nonce?: any): {
    'CryptedHexString': string;
    'rawCrypted': any;
    'NonceHexString': string;
    'rawNonce': any;
  };
  boxOpenEasy(ciphertext: any, public_key: any, private_key: any, nonce: any): {
    'string': string;
    'raw': any;
  };
  boxKeyPaired(): {
    'private_key': any;
    'public_key': any;
  };
  passwordHash(password: string, opslimit?: number, memlimit?: number): {
    'plainHash': string;
    'hashHexString': string;
    'rawHash': any;
  };
  passwordHashVerify(plainHash: any, password: string): boolean;
  binTohex(binary: any): string;
  hexTobin(hex: string): any;
  bytesToBase64(data: any, variant?: Base64Variant): string;
  base64Tobytes(base64String: string, variant?: Base64Variant): any;
  cryptoAuth(msg: string): {
    'CryptedHexString': string;
    'rawCrypted': any;
    'KeyHexString': string;
    'rawKey': any;
  };
  cryptoAuthVerify(ciphertext: any, msg: string, key: any): boolean;
  SHA2Hash(msg: string, type?: number): {
    'hexString': string;
    'raw': any;
  };
  stringTodata(text: string): any;
  dataTostring(data: any): any;
}
