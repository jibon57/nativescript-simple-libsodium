[![npm](https://img.shields.io/npm/v/nativescript-simple-libsodium.svg)](https://www.npmjs.com/package/nativescript-simple-libsodium)
[![npm](https://img.shields.io/npm/dt/nativescript-simple-libsodium.svg?label=npm%20downloads)](https://www.npmjs.com/package/nativescript-simple-libsodium)


# NativeScript Simple Libsodium

[Sodium](https://github.com/jedisct1/libsodium) is a new, easy-to-use software library for encryption, decryption, signatures, password hashing and more. It's cross-compilable & support most of the modern devices. Using this plugin you will be able to use it directly with your NativeScript project.

For iOS I have compiled it directly from source code. For Android I have used [Lazysodium](https://github.com/terl/lazysodium-android) native library.

 **Note:** I am not an expert of neigher iOS nor Android. So, please contribute if you think something you can do better :)

 ## Platforms supported 

1. iOS
2. Android

Libsodium can be use with other programming languages too. You can get more references from here: https://libsodium.gitbook.io/doc/bindings_for_other_languages

## Installation

```javascript
tns plugin add nativescript-simple-libsodium
```

## Usage 

**Import**

TS/Angular:

```javascript
import { SimpleLibsodium, AEDMethod, AEDValues, Base64Variant, Keybytes, Noncebytes } from 'nativescript-simple-libsodium';

let simpleLibsodium = new SimpleLibsodium();
```

JavaScript:
```javascript
var mSimpleLibsodium = require("nativescript-simple-libsodium");
var simpleLibsodium = new mSimpleLibsodium.SimpleLibsodium();
```

Please check the demo project for more details example.

**Generate Random Data:**

```javascript
simpleLibsodium.generateRandomData();
 // OR
simpleLibsodium.generateKeyWithSuppliedString("Jibon Costa"); // Keep in mind that in order to produce the same key from the same password, the same algorithm, the same salt, and the same values for opslimit and memlimit have to be used. Therefore, these parameters have to be stored for each user.
```

**AED Encryption/Decryption:**

```javascript
let key = this.simpleLibsodium.generateRandomData(AEDValues.XCHACHA20POLY1305_IETF_KEYBYTES);
// or let key = this.simpleLibsodium.generateKeyWithSuppliedString("myKey", AEDValues.XCHACHA20POLY1305_IETF_KEYBYTES);

let enc = this.simpleLibsodium.AEDEncrypt(AEDMethod.XCHACHA20_POLY1305_IETF, "Hello World", key.raw);

console.dir(enc);

let dec = this.simpleLibsodium.AEDDecrypt(AEDMethod.XCHACHA20_POLY1305_IETF, enc.rawCrypted, key.raw, enc.rawNonce);

console.dir(dec);
```

**Secret Box:**

```javascript
let key = this.simpleLibsodium.generateRandomData(Keybytes.SECRETBOX_KEYBYTES);
// or let key = this.simpleLibsodium.generateKeyWithSuppliedString("myKey", Keybytes.SECRETBOX_KEYBYTES);

let enc = this.simpleLibsodium.secretBoxEncrypt("Hello World", key.raw);

console.dir(enc);

let dec = this.simpleLibsodium.secretBoxOpen(enc.rawCrypted, key.raw, enc.rawNonce);

console.dir(dec);
```

**Salsa20:**

```javascript
let key = this.simpleLibsodium.generateRandomData(Keybytes.STREAM_KEYBYTES);
// or let key = this.simpleLibsodium.generateKeyWithSuppliedString("myKey", Keybytes.STREAM_KEYBYTES);

let enc = this.simpleLibsodium.xSalsa20Encrypt("Hello World", key.raw);

console.dir(enc);

let dec = this.simpleLibsodium.xSalsa20Decrypt(enc.rawCrypted, key.raw, enc.rawNonce);

console.dir(dec);
```

**Box Easy:**

```javascript
let bob = this.simpleLibsodium.boxKeyPaired();
let alice = this.simpleLibsodium.boxKeyPaired();

// Bob sending message to Alice. So, here will need Alice's public key & Bob's private/secret key
let enc = this.simpleLibsodium.boxEasy("Hello World", alice.public_key, bob.private_key);

console.dir(enc);

// Alice got the message from Bob. Now Alice need his private key & Bob's public key.
let dec = this.simpleLibsodium.boxOpenEasy(enc.rawCrypted, enc.rawNonce, bob.public_key, alice.private_key);

console.dir(dec);
```

**Password Hash/Verification:**

```javascript
let enc = this.simpleLibsodium.passwordHash("MyPassword");

console.dir(enc);

if (this.simpleLibsodium.passwordHashVerify(enc.plainHash, "MyPassword")) {
  console.log("Password Matched!");
} else {
  console.log("Password invalid!");
}
```

**Crypto Authentication/Verification:**

```javascript
let enc = this.simpleLibsodium.cryptoAuth("Jibon Costa");

console.dir(enc);

if (this.simpleLibsodium.cryptoAuthVerify(enc.rawCrypted, "Jibon Costa", enc.rawKey)) {
  console.log("Matched !")
} else {
  console.log("Didn't match")
}
```

**SHA-256/512 Hash:**

```javascript
let enc = this.simpleLibsodium.SHA2Hash("MyPassword", 512); // or 256
console.dir(enc);
```

## Methods/API
    
| Methods | Description | Reference |
| --- | --- | --- |
| generateRandomData(length?: number) | Generate Random Data | https://libsodium.gitbook.io/doc/generating_random_data |
| generateKeyWithSuppliedString(mykey: string, length?: number, salt?: any, opslimit?: number, memlimit?: number) | Generate Random Data with Key. Algorithm: `crypto_pwhash_ALG_ARGON2I13`, opslimit: `crypto_pwhash_OPSLIMIT_MIN`, memlimit: `crypto_pwhash_MEMLIMIT_MIN`. If you don't provide anything for `salt` then it will generate automatically & return back as output. Keep in mind that in order to produce the same key from the same password, the same algorithm, the same salt, and the same values for opslimit and memlimit have to be used. | https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function#key-derivation |
| AEDEncrypt(method: AEDMethod, msg: string, key: any, nonce?: any, additionalMsg?: string) | AED Encryption. Here `nonce` & `additionalMsg` are optional. If you don't insert anything as `nonce` then it will generate `nonce` automatically. If you don't insert anything as `additionalMsg` then `Hexadecimal` value of `nonce` will be use as `additionalMsg`. | https://libsodium.gitbook.io/doc/secret-key_cryptography/aead |
| AEDDecrypt(method: AEDMethod, encrypData: any, key: any, nonce: any, additionalMsg?: string) | AED Decryption. Here `encrypData`, `key` & `nonce` should need to be binary data. If you have `Hexadecimal` or `base64` string then you will need to convert before using. In this case you can use `hexTobin()` or `base64Tobytes()` methods to convert. | https://libsodium.gitbook.io/doc/secret-key_cryptography/aead |
| secretBoxEncrypt(text: string, key: any, nonce?: any) | Authenticated encryption. If you don't insert anything as `nonce` then it will generate `nonce` automatically. | https://libsodium.gitbook.io/doc/secret-key_cryptography/authenticated_encryption#combined-mode |
| secretBoxOpen(encrypData: any, key: any, nonce: any) | Authenticated decryption. Here `encrypData`, `key` & `nonce` should need to be binary data. If you have `Hexadecimal` or `base64` string then you will need to convert before using. In this case you can use `hexTobin()` or `base64Tobytes()` methods to convert. | https://libsodium.gitbook.io/doc/secret-key_cryptography/authenticated_encryption#combined-mode |
| xSalsa20Encrypt(message: string, key: any, nonce?: any) | Stream cipher. If you don't insert anything as `nonce` then it will generate `nonce` automatically. | https://libsodium.gitbook.io/doc/advanced/stream_ciphers/xsalsa20 |
| xSalsa20Decrypt(encrypData: any, key: any, nonce: any) | Stream cipher. Here `encrypData`, `key` & `nonce` should need to be binary data. If you have `Hexadecimal` or `base64` string then you will need to convert before using. In this case you can use `hexTobin()` or `base64Tobytes()` methods to convert. | https://libsodium.gitbook.io/doc/advanced/stream_ciphers/xsalsa20 |
| boxEasy(msg: string, public_key: any, private_key: any, nonce?: any) | Authenticated encryption with key pair. If you don't insert anything as `nonce` then it will generate `nonce` automatically. | https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption |
| boxOpenEasy(ciphertext: any, public_key: any, private_key: any, nonce: any) | Authenticated decryption with key pair. Here `ciphertext`, `public_key`, `private_key` & `nonce` should need to be binary data. If you have `Hexadecimal` or `base64` string then you will need to convert before using. In this case you can use `hexTobin()` or `base64Tobytes()` methods to convert.  | https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption |
| boxKeyPaired() | Key pair generation | https://libsodium.gitbook.io/doc/public-key_cryptography/authenticated_encryption#key-pair-generation |
| passwordHash(password: string), opslimit?: number, memlimit?: number | Password hash for storage. opslimit: `crypto_pwhash_OPSLIMIT_INTERACTIVE`, memlimit: `crypto_pwhash_MEMLIMIT_INTERACTIVE` | https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function#password-storage |
| passwordHashVerify(plainHash: any, password: string) | Password verification. Here the value `plainHash` should need to plain text/string. | https://libsodium.gitbook.io/doc/password_hashing/the_argon2i_function#password-storage |
| cryptoAuth(msg: string) | Authentication | https://libsodium.gitbook.io/doc/secret-key_cryptography/secret-key_authentication |
| cryptoAuthVerify(ciphertext: any, msg: string, key: any) | Authentication verification. Here the value `ciphertext` & `key` should need to be binary data. If you have `Hexadecimal` or `base64` string then you will need to convert before using. In this case you can use `hexTobin()` or `base64Tobytes()` methods to convert. | https://libsodium.gitbook.io/doc/secret-key_cryptography/secret-key_authentication#usage |
| SHA2Hash(msg: string, type?: number) | SHA-2 (SHA 256/512). The value of `type` will be either `256` or `512` | https://libsodium.gitbook.io/doc/advanced/sha-2_hash_function |
| binTohex(binary: any) | Hexadecimal encoding | https://libsodium.gitbook.io/doc/helpers#hexadecimal-encoding-decoding |
| hexTobin(hex: string) | Hexadecimal decoding | https://libsodium.gitbook.io/doc/helpers#hexadecimal-encoding-decoding |
| bytesToBase64(data: any, variant?: Base64Variant) | Base64 encoding | https://libsodium.gitbook.io/doc/helpers#base64-encoding-decoding. |
| base64Tobytes(base64String: string, variant?: Base64Variant) | Base64 decoding | https://libsodium.gitbook.io/doc/helpers#base64-encoding-decoding |
| stringTodata(text: string) | String text to Binary | Native Implementation |
| dataTostring(data: any) | Binary to text | Native Implementation |



**Note: You can add more methods or API from core sodium package to your project easily.** 

Android:

```javascript
let simpleLibsodium = new SimpleLibsodium();
let sodium = simpleLibsodium.sodium
// now you can call any method/api from core sodium package.
sodium.crypto_secretbox_keygen();
```

iOS:

```javascript
// From iOS you will be able to call the methods directly.
crypto_secretbox_keygen();
```

For getting typescript typings support you can add following lines in you `references.d.ts` file:

```javascript
/// <reference path="./node_modules/nativescript-simple-libsodium/typingz/android.d.ts" />
/// <reference path="./node_modules/nativescript-simple-libsodium/typingz/objc!sodium.d.ts" />
```

## License

Apache License Version 2.0, January 2004

