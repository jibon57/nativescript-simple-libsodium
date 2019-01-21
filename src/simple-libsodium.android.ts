import { Common, AEDMethod, AEDValues, Base64Variant, Keybytes } from './simple-libsodium.common';

const SodiumAndroid = com.goterl.lazycode.lazysodium.SodiumAndroid;
const LazySodiumAndroid = com.goterl.lazycode.lazysodium.LazySodiumAndroid;
const Interfaces = com.goterl.lazycode.lazysodium.interfaces;
const Utils = com.goterl.lazycode.lazysodium.utils;

export class SimpleLibsodium extends Common {

    public sodium: com.goterl.lazycode.lazysodium.SodiumAndroid;
    public lazySodium: com.goterl.lazycode.lazysodium.LazySodiumAndroid;

    constructor() {
        super();

        let sodium = new SodiumAndroid();
        let lazySodium = new LazySodiumAndroid(sodium);
        sodium = lazySodium.getSodium();

        this.sodium = sodium;
        this.lazySodium = lazySodium;

        this.sodium.sodium_init();
    }

    /**
     * generateRandomData
     */
    public generateRandomData(length: number = 32) {

        this.sodium.sodium_init();

        let ramdom = this.lazySodium.randomBytesBuf(length);

        return {
            'hexString': this.binTohex(ramdom),
            'raw': ramdom
        };
    }

    /**
     * generateKeyWithSuppliedString
     */
    public generateKeyWithSuppliedString(mykey: string, length: number = 32, salt: any = '') {

        this.sodium.sodium_init();

        let alg = Interfaces.PwHash.Alg.getDefault();
        if (salt === "") {
            salt = this.generateRandomData(Keybytes.PWHASH_SALTBYTES).raw; // Interfaces.PwHash.SALTBYTES
        }
        let out = this.lazySodium.cryptoPwHash(mykey, length, salt, Interfaces.PwHash.OPSLIMIT_INTERACTIVE, Interfaces.PwHash.MEMLIMIT_INTERACTIVE, alg);

        return {
            'hexString': out,
            'raw': this.hexTobin(out),
            'saltHexString': this.binTohex(salt),
            'rawSalt': salt
        };

    }

    /**
     * AEDEncrypt
     */
    public AEDEncrypt(method: AEDMethod, msg: string, key: any, nonce: any = '', additionalMsg: string = '') {

        this.sodium.sodium_init();

        let outData;
        let output = {
            'status': false,
            'msg': 'error'
        };
        let rawKey = Utils.Key.fromBytes(key);

        switch (method) {

            case AEDMethod.CHACHA20_POLY1305:

                if (nonce === '') {
                    nonce = this.generateRandomData(AEDValues.CHACHA20POLY1305_NPUBBYTES).raw;
                }
                if (additionalMsg === '') {
                    additionalMsg = this.binTohex(nonce);
                }
                if (key.length !== AEDValues.CHACHA20POLY1305_KEYBYTES) {
                    output.msg = "Invalid Key";
                    return output;
                }
                outData = this.lazySodium.encrypt(msg, additionalMsg, nonce, rawKey, Interfaces.AEAD.Method.CHACHA20_POLY1305);
                break;

            case AEDMethod.CHACHA20_POLY1305_IETF:

                if (nonce === '') {
                    nonce = this.generateRandomData(AEDValues.CHACHA20POLY1305_IETF_NPUBBYTES).raw;
                }

                if (additionalMsg === '') {
                    additionalMsg = this.binTohex(nonce);
                }

                if (key.length !== AEDValues.CHACHA20POLY1305_IETF_KEYBYTES) {
                    output.msg = "Invalid Key";
                    return output;
                }
                outData = this.lazySodium.encrypt(msg, additionalMsg, nonce, rawKey, Interfaces.AEAD.Method.CHACHA20_POLY1305_IETF);
                break;

            case AEDMethod.XCHACHA20_POLY1305_IETF:

                if (nonce === '') {
                    nonce = this.generateRandomData(AEDValues.XCHACHA20POLY1305_IETF_NPUBBYTES).raw;
                }

                if (additionalMsg === '') {
                    additionalMsg = this.binTohex(nonce);
                }

                if (key.length !== AEDValues.XCHACHA20POLY1305_IETF_KEYBYTES) {
                    output.msg = "Invalid Key";
                    return output;
                }
                outData = this.lazySodium.encrypt(msg, additionalMsg, nonce, rawKey, Interfaces.AEAD.Method.XCHACHA20_POLY1305_IETF);

                break;

            case AEDMethod.AES256GCM:

                if (nonce === '') {
                    nonce = this.generateRandomData(AEDValues.AES256GCM_NPUBBYTES).raw;
                }

                if (additionalMsg === '') {
                    additionalMsg = this.binTohex(nonce);
                }

                if (key.length !== AEDValues.AES256GCM_KEYBYTES) {
                    output.msg = "Invalid Key";
                    return output;
                }
                outData = this.lazySodium.encrypt(msg, additionalMsg, nonce, rawKey, Interfaces.AEAD.Method.AES256GCM);

                break;
        }

        return {
            'status': true,
            'CryptedHexString': outData,
            'rawCrypted': this.hexTobin(outData),
            'nonceHexString': this.binTohex(nonce),
            'rawNonce': nonce
        };
    }

    /**
     * AEDDecrypt
     */
    public AEDDecrypt(method: AEDMethod, encrypData: any, key: any, nonce: any, additionalMsg: string = '') {

        this.sodium.sodium_init();

        let outData;
        encrypData = this.binTohex(encrypData);
        key = Utils.Key.fromBytes(key);

        if (additionalMsg === '') {
            additionalMsg = this.binTohex(nonce);
        }

        switch (method) {

            case AEDMethod.CHACHA20_POLY1305:

                outData = this.lazySodium.decrypt(encrypData, additionalMsg, nonce, key, Interfaces.AEAD.Method.CHACHA20_POLY1305);

                break;

            case AEDMethod.CHACHA20_POLY1305_IETF:

                outData = this.lazySodium.decrypt(encrypData, additionalMsg, nonce, key, Interfaces.AEAD.Method.CHACHA20_POLY1305_IETF);

                break;

            case AEDMethod.XCHACHA20_POLY1305_IETF:

                outData = this.lazySodium.decrypt(encrypData, additionalMsg, nonce, key, Interfaces.AEAD.Method.XCHACHA20_POLY1305_IETF);

                break;

            case AEDMethod.AES256GCM:

                outData = this.lazySodium.decrypt(encrypData, additionalMsg, nonce, key, Interfaces.AEAD.Method.AES256GCM);

                break;
        }

        return {
            'string': outData,
            'raw': this.stringTodata(outData)
        };
    }

    /**
     * secretBoxEncrypt
     */
    public secretBoxEncrypt(message: string, key: any, nonce: any = '') {

        this.sodium.sodium_init();

        if (key.length !== Interfaces.SecretBox.KEYBYTES) {
            return {
                'status': false,
                'msg': 'Invalid key. Key length should be 32'
            };
        }

        if (nonce === '') {
            nonce = this.generateRandomData(Interfaces.SecretBox.NONCEBYTES).raw;
        }

        let msg = this.stringTodata(message);
        let outData = Array.create("byte", Interfaces.SecretBox.MACBYTES + msg.length);

        this.sodium.crypto_secretbox_easy(outData, msg, msg.length, nonce, key);

        return {
            'status': true,
            'CryptedHexString': this.binTohex(outData),
            'rawCrypted': outData,
            'nonceHexString': this.binTohex(nonce),
            'rawNonce': nonce
        };
    }

    /**
     * secretBoxOpen
     */
    public secretBoxOpen(encrypData: any, key: any, nonce: any) {

        this.sodium.sodium_init();

        let outData = Array.create("byte", encrypData.length - Interfaces.SecretBox.MACBYTES);

        this.sodium.crypto_secretbox_open_easy(outData, encrypData, encrypData.length, nonce, key);

        return {
            'string': this.dataTostring(outData),
            'raw': outData
        };
    }

    /**
     * xSalsa20Encrypt
     */
    public xSalsa20Encrypt(message: string, key: any, nonce: any = '') {

        this.sodium.sodium_init();

        if (nonce === '') {
            nonce = this.generateRandomData(Interfaces.Stream.SALSA20_NONCEBYTES).raw;
        }
        if (key.length !== Interfaces.Stream.SALSA20_KEYBYTES) {
            return {
                'status': false,
                'msg': "Invalid Key"
            };
        }
        key = Utils.Key.fromBytes(key);

        let outData = this.lazySodium.cryptoStreamXor(message, nonce, key, Interfaces.Stream.Method.SALSA20);

        return {
            'status': true,
            'CryptedHexString': outData,
            'rawCrypted': this.hexTobin(outData),
            'NonceHexString': this.binTohex(nonce),
            'rawNonce': nonce
        };
    }

    /**
     * xSalsa20Decrypt
     */
    public xSalsa20Decrypt(encrypData: any, key: any, nonce: any) {

        this.sodium.sodium_init();

        key = Utils.Key.fromBytes(key);
        encrypData = this.binTohex(encrypData);

        let outData = this.lazySodium.cryptoStreamXorDecrypt(encrypData, nonce, key, Interfaces.Stream.Method.SALSA20);

        return {
            'string': outData,
            'raw': this.stringTodata(outData)
        };
    }

    /**
     * boxEasy
     */
    public boxEasy(msg: string, public_key: any, private_key: any, nonce: any = "") {

        this.sodium.sodium_init();

        let keyPair = new Utils.KeyPair(Utils.Key.fromBytes(public_key), Utils.Key.fromBytes(private_key));

        if (nonce === "") {
            nonce = this.generateRandomData(Interfaces.Box.NONCEBYTES).raw;
        }

        let outData = this.lazySodium.cryptoBoxEasy(msg, nonce, keyPair);

        return {
            'CryptedHexString': outData,
            'rawCrypted': this.hexTobin(outData),
            'NonceHexString': this.binTohex(nonce),
            'rawNonce': nonce
        };
    }

    /**
     * boxOpenEasy
     */
    public boxOpenEasy(ciphertext: any, nonce: any, public_key: any, private_key: any) {

        this.sodium.sodium_init();

        let keyPair = new Utils.KeyPair(Utils.Key.fromBytes(public_key), Utils.Key.fromBytes(private_key));

        ciphertext = this.binTohex(ciphertext);

        let outData = this.lazySodium.cryptoBoxOpenEasy(ciphertext, nonce, keyPair);

        return {
            'string': outData,
            'raw': this.stringTodata(outData)
        };
    }

    /**
     * boxKeyPaired
    */
    public boxKeyPaired() {

        this.sodium.sodium_init();

        let keys = this.lazySodium.cryptoBoxKeypair();
        return {
            'private_key': keys.getSecretKey().getAsBytes(),
            'public_key': keys.getPublicKey().getAsBytes()
        };
    }

    /**
     * passwordHash
     */
    public passwordHash(password: string) {

        this.sodium.sodium_init();

        let outData = this.lazySodium.cryptoPwHashStrRemoveNulls(password, Interfaces.PwHash.OPSLIMIT_INTERACTIVE, Interfaces.PwHash.MEMLIMIT_INTERACTIVE);

        let rawHash = this.hexTobin(outData);
        let plainHash = this.dataTostring(rawHash);

        return {
            'plainHash': plainHash,
            'hashHexString': outData,
            'rawHash': rawHash
        };
    }

    /**
     * passwordHashVerify
     */
    public passwordHashVerify(plainHash: any, password: string) {

        this.sodium.sodium_init();

        plainHash = this.stringTodata(plainHash);
        plainHash = this.binTohex(plainHash);

        return this.lazySodium.cryptoPwHashStrVerify(plainHash, password);
    }

    /**
     * binTohex
     */
    public binTohex(binary: any) {
        this.sodium.sodium_init();
        return this.lazySodium.sodiumBin2Hex(binary);
    }

    /**
     * hexTobin
     */
    public hexTobin(hex: any) {
        this.sodium.sodium_init();
        return this.lazySodium.sodiumHex2Bin(hex);
    }

    /**
     * bytesToBase64
     */
    public bytesToBase64(data: any, variant: Base64Variant = Base64Variant.sodium_base64_VARIANT_ORIGINAL) {

        this.sodium.sodium_init();

        let encoded_len = this.sodium.sodium_base64_encoded_len(data.length, variant);
        let out = Array.create("byte", encoded_len);
        this.sodium.sodium_bin2base64(out, encoded_len, data, data.length, variant);

        return this.dataTostring(out);
    }

    /**
     * base642bytes
     */
    public base64Tobytes(base64String: string, variant: Base64Variant = Base64Variant.sodium_base64_VARIANT_ORIGINAL) {

        this.sodium.sodium_init();

        let rawData: any = this.stringTodata(base64String);
        let binBytesCapacity = Math.round((rawData.length * 3 / 4) - 1);

        let outData = Array.create("byte", binBytesCapacity);

        this.sodium.sodium_base642bin(outData, binBytesCapacity, rawData, rawData.length, null, 0, null, variant);

        return outData;
    }

    /**
     * stringTodata
     */
    public stringTodata(text: string) {
        let out = new java.lang.String(text);
        return out.getBytes();
    }

    /**
     * dataTostring
     */
    public dataTostring(data: any) {
        return new java.lang.String(data, 'UTF-8').toString();
    }

}
