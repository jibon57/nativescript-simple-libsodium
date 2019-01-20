import { Common, AEDMethod, AEDValues, Base64Variant } from "./simple-libsodium.common";

export class SimpleLibsodium extends Common {

    /**
     * generateRandomData
     */
    public generateRandomData(length: number = 32) {

        let outData = NSMutableData.dataWithLength(length);
        randombytes_buf(outData.mutableBytes, length);

        return {
            'hexString': this.binTohex(outData),
            'raw': outData
        };
    }

    /**
     * generateKeyWithSuppliedString
     */
    public generateKeyWithSuppliedString(mykey: string, saltSize = 32) {

        let out: any = NSMutableData.dataWithLength(saltSize);
        let passwd: any = this.nsstringTOnsdata(mykey);
        let salt: any = this.generateRandomData(crypto_pwhash_saltbytes());
        let alg = crypto_pwhash_alg_argon2id13(); // crypto_pwhash_alg_default();

        crypto_pwhash(out.mutableBytes, saltSize, passwd.bytes, passwd.length, salt.raw.bytes, crypto_pwhash_opslimit_interactive(), crypto_pwhash_memlimit_interactive(), alg);

        return {
            'hexString': this.binTohex(out),
            'raw': out
        };
    }

    /**
     * AEDEncrypt
     */
    public AEDEncrypt(method: AEDMethod, msg: string, key: NSData, nonce: NSData = null, additionalMsg: string = '') {

        let outData, ciphertext_len, additionalData, rawNonce;
        let nKey: any = key;

        let output = {
            'status': false,
            'msg': 'error'
        };

        let cipher: any = this.nsstringTOnsdata(msg);

        switch (method) {
            case AEDMethod.CHACHA20_POLY1305:

                if (nonce == null) {
                    rawNonce = this.generateRandomData(AEDValues.CHACHA20POLY1305_NPUBBYTES).raw;
                } else {
                    rawNonce = nonce;
                }

                if (additionalMsg === '') {
                    additionalData = rawNonce;
                } else {
                    additionalData = this.nsstringTOnsdata(additionalMsg);
                }

                if (key.length !== AEDValues.CHACHA20POLY1305_KEYBYTES) {
                    output.msg = "Invalid Key";
                    return output;
                }

                outData = NSMutableData.dataWithLength(cipher.length + AEDValues.CHACHA20POLY1305_ABYTES);
                ciphertext_len = malloc(0);

                crypto_aead_chacha20poly1305_encrypt(outData.mutableBytes, ciphertext_len, cipher.bytes, cipher.length, additionalData.bytes, additionalData.length, null, rawNonce.bytes, nKey.bytes);

                break;

            case AEDMethod.CHACHA20_POLY1305_IETF:

                if (nonce == null) {
                    rawNonce = this.generateRandomData(AEDValues.CHACHA20POLY1305_IETF_NPUBBYTES).raw;
                } else {
                    rawNonce = nonce;
                }

                if (additionalMsg === '') {
                    additionalData = rawNonce;
                } else {
                    additionalData = this.nsstringTOnsdata(additionalMsg);
                }

                if (key.length !== AEDValues.CHACHA20POLY1305_IETF_KEYBYTES) {
                    output.msg = "Invalid Key";
                    return output;
                }

                outData = NSMutableData.dataWithLength(cipher.length + AEDValues.CHACHA20POLY1305_IETF_ABYTES);
                ciphertext_len = malloc(0);

                crypto_aead_chacha20poly1305_ietf_encrypt(outData.mutableBytes, ciphertext_len, cipher.bytes, cipher.length, additionalData.bytes, additionalData.length, null, rawNonce.bytes, nKey.bytes);
                break;

            case AEDMethod.XCHACHA20_POLY1305_IETF:

                if (nonce == null) {
                    rawNonce = this.generateRandomData(AEDValues.XCHACHA20POLY1305_IETF_NPUBBYTES).raw;
                } else {
                    rawNonce = nonce;
                }

                if (additionalMsg === '') {
                    additionalData = rawNonce;
                } else {
                    additionalData = this.nsstringTOnsdata(additionalMsg);
                }

                if (key.length !== AEDValues.XCHACHA20POLY1305_IETF_KEYBYTES) {
                    output.msg = "Invalid Key";
                    return output;
                }

                outData = NSMutableData.dataWithLength(cipher.length + AEDValues.XCHACHA20POLY1305_IETF_ABYTES);
                ciphertext_len = malloc(0);

                crypto_aead_xchacha20poly1305_ietf_encrypt(outData.mutableBytes, ciphertext_len, cipher.bytes, cipher.length, additionalData.bytes, additionalData.length, null, rawNonce.bytes, nKey.bytes);
                break;

            case AEDMethod.AES256GCM:

                if (nonce == null) {
                    rawNonce = this.generateRandomData(AEDValues.AES256GCM_NPUBBYTES).raw;
                } else {
                    rawNonce = nonce;
                }

                if (additionalMsg === '') {
                    additionalData = rawNonce;
                } else {
                    additionalData = this.nsstringTOnsdata(additionalMsg);
                }

                if (key.length !== AEDValues.AES256GCM_KEYBYTES) {
                    output.msg = "Invalid Key";
                    return output;
                }

                outData = NSMutableData.dataWithLength(cipher.length + AEDValues.AES256GCM_ABYTES);
                ciphertext_len = malloc(0);

                crypto_aead_aes256gcm_encrypt(outData.mutableBytes, ciphertext_len, cipher.bytes, cipher.length, additionalData.bytes, additionalData.length, null, rawNonce.bytes, nKey.bytes);
                break;
        }

        let rawCrypted: NSData = NSData.alloc().initWithData(outData);

        return {
            'status': true,
            'CryptedHexString': this.binTohex(outData),
            'rawCrypted': rawCrypted,
            'nonceHexString': this.binTohex(rawNonce),
            'rawNonce': rawNonce
        };

    }

    /**
     * AEDDecrypt
     */
    public AEDDecrypt(method: AEDMethod, encrypData: NSData, key: NSData, nonce: NSData, additionalMsg: string = '') {

        let rawAdditionalMsg;
        let rawNonce: any = nonce;
        let rawKey: any = key;
        let rawData: any = encrypData;
        let outData;

        if (additionalMsg !== '') {
            rawAdditionalMsg = this.nsstringTOnsdata(additionalMsg);
        } else {
            rawAdditionalMsg = nonce;
        }

        switch (method) {

            case AEDMethod.CHACHA20_POLY1305:

                outData = NSMutableData.dataWithLength(rawData.length - AEDValues.CHACHA20POLY1305_ABYTES);

                crypto_aead_chacha20poly1305_decrypt(outData.bytes, malloc(0), null, rawData.bytes, rawData.length, rawAdditionalMsg.bytes, rawAdditionalMsg.length, rawNonce.bytes, rawKey.bytes);

                break;

            case AEDMethod.CHACHA20_POLY1305_IETF:

                outData = NSMutableData.dataWithLength(rawData.length - AEDValues.CHACHA20POLY1305_IETF_ABYTES);

                crypto_aead_chacha20poly1305_ietf_decrypt(outData.bytes, malloc(0), null, rawData.bytes, rawData.length, rawAdditionalMsg.bytes, rawAdditionalMsg.length, rawNonce.bytes, rawKey.bytes);

                break;

            case AEDMethod.XCHACHA20_POLY1305_IETF:

                outData = NSMutableData.dataWithLength(rawData.length - AEDValues.XCHACHA20POLY1305_IETF_ABYTES);

                crypto_aead_xchacha20poly1305_ietf_decrypt(outData.bytes, malloc(0), null, rawData.bytes, rawData.length, rawAdditionalMsg.bytes, rawAdditionalMsg.length, rawNonce.bytes, rawKey.bytes);

                break;

            case AEDMethod.AES256GCM:

                outData = NSMutableData.dataWithLength(rawData.length - AEDValues.AES256GCM_ABYTES);

                crypto_aead_aes256gcm_decrypt(outData.bytes, malloc(0), null, rawData.bytes, rawData.length, rawAdditionalMsg.bytes, rawAdditionalMsg.length, rawNonce.bytes, rawKey.bytes);

                break;
        }

        return {
            'string': this.nsdataTOnsstring(outData),
            'raw': outData
        };
    }

    /**
     * secretBoxEncrypt
     */
    public secretBoxEncrypt(text: string, key: NSData, nonce: NSData = null) {

        let msg: any = this.nsstringTOnsdata(text);
        let outLen = crypto_secretbox_macbytes() + msg.length;
        let outData: any = NSMutableData.dataWithLength(outLen);
        let rawNonce: any = nonce;
        let rawKey: any = key;

        if (key.length !== crypto_secretbox_keybytes()) {
            return {
                'status': false,
                'msg': 'Invalid key. Key length should be 32'
            };
        }
        if (nonce == null) {
            rawNonce = this.generateRandomData(crypto_secretbox_noncebytes()).raw;
        }

        crypto_secretbox_easy(outData.mutableBytes, msg.bytes, msg.length, rawNonce.bytes, rawKey.bytes);

        return {
            'status': true,
            'CryptedHexString': this.binTohex(outData),
            'rawCrypted': outData,
            'nonceHexString': this.binTohex(rawNonce),
            'rawNonce': rawNonce
        };
    }

    /**
     * secretBoxOpen
     */
    public secretBoxOpen(encrypData: NSData, key: NSData, nonce: NSData) {

        let rawData: any = encrypData;
        let rawNonce: any = nonce;
        let rawKey: any = key;

        let out: any = NSMutableData.dataWithLength(encrypData.length - crypto_secretbox_macbytes());

        crypto_secretbox_open_easy(out.mutableBytes, rawData.bytes, rawData.length, rawNonce.bytes, rawKey.bytes);

        return {
            'string': this.nsdataTOnsstring(out),
            'raw': out
        };
    }

    /**
     * xSalsa20Encrypt
     */
    public xSalsa20Encrypt(message: string, key: NSData, nonce: NSData = null) {
        let rawNonce: any = nonce;
        let rawKey: any = key;
        if (nonce == null) {
            rawNonce = this.generateRandomData(crypto_stream_noncebytes()).raw;
        }
        if (key.length !== crypto_stream_keybytes()) {
            return {
                'status': false,
                'msg': "Invalid Key"
            };
        }

        let msg: any = this.nsstringTOnsdata(message);
        let outData: any = NSMutableData.dataWithLength(msg.length);

        crypto_stream_xor(outData.mutableBytes, msg.bytes, msg.length, rawNonce.bytes, rawKey.bytes);

        return {
            'status': true,
            'CryptedHexString': this.binTohex(outData),
            'rawCrypted': outData,
            'NonceHexString': this.binTohex(rawNonce),
            'rawNonce': rawNonce
        };

    }

    /**
     * xSalsa20Decrypt
     */
    public xSalsa20Decrypt(encrypData: NSData, key: NSData, nonce: NSData) {

        let rawNonce: any = nonce;
        let rawKey: any = key;
        let msg: any = encrypData;

        let outData: any = NSMutableData.dataWithLength(msg.length);

        crypto_stream_xor(outData.mutableBytes, msg.bytes, msg.length, rawNonce.bytes, rawKey.bytes);

        return {
            'string': this.nsdataTOnsstring(outData),
            'raw': outData
        };
    }

    /**
     * boxEasy
     */
    public boxEasy(msg: string, public_key: any, private_key: any, nonce: NSData = null) {

        let rawMsg: any = this.nsstringTOnsdata(msg);
        let outLen = rawMsg.length + crypto_box_macbytes();
        let outData: any = NSMutableData.dataWithLength(outLen);
        let rawNonce: any = nonce;

        if (nonce == null) {
            rawNonce = this.generateRandomData(crypto_box_noncebytes()).raw;
        }

        crypto_box_easy(outData.mutableBytes, rawMsg.bytes, rawMsg.length, rawNonce.bytes, public_key, private_key);

        return {
            'CryptedHexString': this.binTohex(outData),
            'rawCrypted': outData,
            'NonceHexString': this.binTohex(rawNonce),
            'rawNonce': rawNonce
        };
    }

    /**
     * boxOpenEasy
     */
    public boxOpenEasy(ciphertext: NSData, nonce: NSData, public_key: any, private_key: any) {

        let rawNonce: any = nonce;
        let msg: any = ciphertext;

        let outLen = ciphertext.length - crypto_box_macbytes();
        let outData: any = NSMutableData.dataWithLength(outLen);

        crypto_box_open_easy(outData.mutableBytes, msg.bytes, msg.length, rawNonce.bytes, public_key, private_key);

        return {
            'string': this.nsdataTOnsstring(outData),
            'raw': outData
        };
    }

    /**
     * boxKeyPaired
     */
    public boxKeyPaired() {

        let public_key: any = NSMutableData.dataWithLength(crypto_box_publickeybytes());
        let private_key: any = NSMutableData.dataWithLength(crypto_box_secretkeybytes());
        crypto_box_keypair(public_key.bytes, private_key.bytes);

        return {
            'private_key': private_key,
            'public_key': public_key
        };
    }

    /**
     * passwordHash
     */
    public passwordHash(password: string) {

        let passwordData: any = this.nsstringTOnsdata(password);
        let output: any = NSMutableData.dataWithLength(crypto_pwhash_strbytes());

        crypto_pwhash_str(output.bytes, passwordData.bytes, passwordData.length, crypto_pwhash_opslimit_interactive(), crypto_pwhash_memlimit_interactive());

        return {
            'plainHash': this.nsdataTOnsstring(output),
            'hashHexString': this.binTohex(output),
            'rawHash': output
        };
    }

    /**
     * passwordHashVerify
     */
    public passwordHashVerify(plainHash, password: string): boolean {

        let passwordData: any = this.nsstringTOnsdata(password);
        let rawCrypto: any = this.nsstringTOnsdata(plainHash);

        let ver = crypto_pwhash_str_verify(rawCrypto.bytes, passwordData.bytes, passwordData.length);

        if (ver === 0) {
            return true;
        }
        return false;
    }

    /**
     * binTohex
     */
    public binTohex(binary: NSData): NSString {

        let rawBinary: any = binary;
        let hex_maxlen = rawBinary.length * 2 + 1;
        let hex: any = NSMutableData.dataWithLength(hex_maxlen);

        sodium_bin2hex(hex.bytes, hex_maxlen, rawBinary.bytes, rawBinary.length);

        return this.nsdataTOnsstring(hex);
    }

    /**
     * hexTobin
     */
    public hexTobin(hex: string): NSData {

        let hexData: any = this.nsstringTOnsdata(hex);

        let bin_maxlen = hexData.length / 2;
        let bin: any = NSMutableData.dataWithLength(bin_maxlen);

        sodium_hex2bin(bin.bytes, bin_maxlen, hexData.bytes, hexData.length, null, malloc(0), null);

        return bin;
    }

    /**
     * bytesToBase64
     */
    public bytesToBase64(data: NSData, variant: Base64Variant = Base64Variant.sodium_base64_VARIANT_ORIGINAL): NSString {

        let rawData: any = data;
        let encoded_len = sodium_base64_encoded_len(data.length, variant);
        let out: any = NSMutableData.dataWithLength(encoded_len);

        sodium_bin2base64(out.mutableBytes, encoded_len, rawData.bytes, rawData.length, variant);

        return this.nsdataTOnsstring(out);

        // return data.base64Encoding();
    }

    /**
     * base642bytes
     */
    public base64Tobytes(base64String: string, variant: Base64Variant = Base64Variant.sodium_base64_VARIANT_ORIGINAL): NSData {

        let rawData: any = this.nsstringTOnsdata(base64String);
        let binBytesCapacity = Math.round((rawData.length * 3 / 4) - 1);
        let out: any = NSMutableData.dataWithLength(binBytesCapacity);

        sodium_base642bin(out.mutableBytes, binBytesCapacity, rawData.bytes, rawData.length, null, malloc(0), null, variant);

        return out;

        // return NSData.alloc().initWithBase64Encoding(base64String);
    }

    /**
     * nsdataTOnsstring
     */
    public nsdataTOnsstring(data: NSData): NSString {
        return NSString.alloc().initWithDataEncoding(data, NSUTF8StringEncoding);
    }

    /**
     * nsstringTOnsdata
     */
    public nsstringTOnsdata(stringText: string): NSData {
        let nsString = NSString.alloc().initWithString(stringText);
        return nsString.dataUsingEncoding(NSUTF8StringEncoding);
    }

    /**
     * string2data
     */
    public stringTodata(text: string): NSData {
        return this.nsstringTOnsdata(text);
    }

    /**
     * data2string
     */
    public dataTostring(data: NSData): NSString {
        return this.nsdataTOnsstring(data);
    }
}
