
declare function _sodium_alloc_init(): number;

declare function _sodium_runtime_get_cpu_features(): number;

declare function crypto_aead_aes256gcm_abytes(): number;

declare function crypto_aead_aes256gcm_beforenm(ctx_: interop.Pointer | interop.Reference<crypto_aead_aes256gcm_state>, k: string): number;

declare function crypto_aead_aes256gcm_decrypt(m: string, mlen_p: interop.Pointer | interop.Reference<number>, nsec: string, c: string, clen: number, ad: string, adlen: number, npub: string, k: string): number;

declare function crypto_aead_aes256gcm_decrypt_afternm(m: string, mlen_p: interop.Pointer | interop.Reference<number>, nsec: string, c: string, clen: number, ad: string, adlen: number, npub: string, ctx_: interop.Pointer | interop.Reference<crypto_aead_aes256gcm_state>): number;

declare function crypto_aead_aes256gcm_decrypt_detached(m: string, nsec: string, c: string, clen: number, mac: string, ad: string, adlen: number, npub: string, k: string): number;

declare function crypto_aead_aes256gcm_decrypt_detached_afternm(m: string, nsec: string, c: string, clen: number, mac: string, ad: string, adlen: number, npub: string, ctx_: interop.Pointer | interop.Reference<crypto_aead_aes256gcm_state>): number;

declare function crypto_aead_aes256gcm_encrypt(c: string, clen_p: interop.Pointer | interop.Reference<number>, m: string, mlen: number, ad: string, adlen: number, nsec: string, npub: string, k: string): number;

declare function crypto_aead_aes256gcm_encrypt_afternm(c: string, clen_p: interop.Pointer | interop.Reference<number>, m: string, mlen: number, ad: string, adlen: number, nsec: string, npub: string, ctx_: interop.Pointer | interop.Reference<crypto_aead_aes256gcm_state>): number;

declare function crypto_aead_aes256gcm_encrypt_detached(c: string, mac: string, maclen_p: interop.Pointer | interop.Reference<number>, m: string, mlen: number, ad: string, adlen: number, nsec: string, npub: string, k: string): number;

declare function crypto_aead_aes256gcm_encrypt_detached_afternm(c: string, mac: string, maclen_p: interop.Pointer | interop.Reference<number>, m: string, mlen: number, ad: string, adlen: number, nsec: string, npub: string, ctx_: interop.Pointer | interop.Reference<crypto_aead_aes256gcm_state>): number;

declare function crypto_aead_aes256gcm_is_available(): number;

declare function crypto_aead_aes256gcm_keybytes(): number;

declare function crypto_aead_aes256gcm_keygen(k: interop.Reference<number>): void;

declare function crypto_aead_aes256gcm_messagebytes_max(): number;

declare function crypto_aead_aes256gcm_npubbytes(): number;

declare function crypto_aead_aes256gcm_nsecbytes(): number;

interface crypto_aead_aes256gcm_state {
	opaque: interop.Reference<number>;
}
declare var crypto_aead_aes256gcm_state: interop.StructType<crypto_aead_aes256gcm_state>;

declare function crypto_aead_aes256gcm_statebytes(): number;

declare function crypto_aead_chacha20poly1305_abytes(): number;

declare function crypto_aead_chacha20poly1305_decrypt(m: string, mlen_p: interop.Pointer | interop.Reference<number>, nsec: string, c: string, clen: number, ad: string, adlen: number, npub: string, k: string): number;

declare function crypto_aead_chacha20poly1305_decrypt_detached(m: string, nsec: string, c: string, clen: number, mac: string, ad: string, adlen: number, npub: string, k: string): number;

declare function crypto_aead_chacha20poly1305_encrypt(c: string, clen_p: interop.Pointer | interop.Reference<number>, m: string, mlen: number, ad: string, adlen: number, nsec: string, npub: string, k: string): number;

declare function crypto_aead_chacha20poly1305_encrypt_detached(c: string, mac: string, maclen_p: interop.Pointer | interop.Reference<number>, m: string, mlen: number, ad: string, adlen: number, nsec: string, npub: string, k: string): number;

declare function crypto_aead_chacha20poly1305_ietf_abytes(): number;

declare function crypto_aead_chacha20poly1305_ietf_decrypt(m: string, mlen_p: interop.Pointer | interop.Reference<number>, nsec: string, c: string, clen: number, ad: string, adlen: number, npub: string, k: string): number;

declare function crypto_aead_chacha20poly1305_ietf_decrypt_detached(m: string, nsec: string, c: string, clen: number, mac: string, ad: string, adlen: number, npub: string, k: string): number;

declare function crypto_aead_chacha20poly1305_ietf_encrypt(c: string, clen_p: interop.Pointer | interop.Reference<number>, m: string, mlen: number, ad: string, adlen: number, nsec: string, npub: string, k: string): number;

declare function crypto_aead_chacha20poly1305_ietf_encrypt_detached(c: string, mac: string, maclen_p: interop.Pointer | interop.Reference<number>, m: string, mlen: number, ad: string, adlen: number, nsec: string, npub: string, k: string): number;

declare function crypto_aead_chacha20poly1305_ietf_keybytes(): number;

declare function crypto_aead_chacha20poly1305_ietf_keygen(k: interop.Reference<number>): void;

declare function crypto_aead_chacha20poly1305_ietf_messagebytes_max(): number;

declare function crypto_aead_chacha20poly1305_ietf_npubbytes(): number;

declare function crypto_aead_chacha20poly1305_ietf_nsecbytes(): number;

declare function crypto_aead_chacha20poly1305_keybytes(): number;

declare function crypto_aead_chacha20poly1305_keygen(k: interop.Reference<number>): void;

declare function crypto_aead_chacha20poly1305_messagebytes_max(): number;

declare function crypto_aead_chacha20poly1305_npubbytes(): number;

declare function crypto_aead_chacha20poly1305_nsecbytes(): number;

declare function crypto_aead_xchacha20poly1305_ietf_abytes(): number;

declare function crypto_aead_xchacha20poly1305_ietf_decrypt(m: string, mlen_p: interop.Pointer | interop.Reference<number>, nsec: string, c: string, clen: number, ad: string, adlen: number, npub: string, k: string): number;

declare function crypto_aead_xchacha20poly1305_ietf_decrypt_detached(m: string, nsec: string, c: string, clen: number, mac: string, ad: string, adlen: number, npub: string, k: string): number;

declare function crypto_aead_xchacha20poly1305_ietf_encrypt(c: string, clen_p: interop.Pointer | interop.Reference<number>, m: string, mlen: number, ad: string, adlen: number, nsec: string, npub: string, k: string): number;

declare function crypto_aead_xchacha20poly1305_ietf_encrypt_detached(c: string, mac: string, maclen_p: interop.Pointer | interop.Reference<number>, m: string, mlen: number, ad: string, adlen: number, nsec: string, npub: string, k: string): number;

declare function crypto_aead_xchacha20poly1305_ietf_keybytes(): number;

declare function crypto_aead_xchacha20poly1305_ietf_keygen(k: interop.Reference<number>): void;

declare function crypto_aead_xchacha20poly1305_ietf_messagebytes_max(): number;

declare function crypto_aead_xchacha20poly1305_ietf_npubbytes(): number;

declare function crypto_aead_xchacha20poly1305_ietf_nsecbytes(): number;

declare function crypto_auth(out: string, _in: string, inlen: number, k: string): number;

declare function crypto_auth_bytes(): number;

declare function crypto_auth_hmacsha256(out: string, _in: string, inlen: number, k: string): number;

declare function crypto_auth_hmacsha256_bytes(): number;

declare function crypto_auth_hmacsha256_final(state: interop.Pointer | interop.Reference<crypto_auth_hmacsha256_state>, out: string): number;

declare function crypto_auth_hmacsha256_init(state: interop.Pointer | interop.Reference<crypto_auth_hmacsha256_state>, key: string, keylen: number): number;

declare function crypto_auth_hmacsha256_keybytes(): number;

declare function crypto_auth_hmacsha256_keygen(k: interop.Reference<number>): void;

interface crypto_auth_hmacsha256_state {
	ictx: crypto_hash_sha256_state;
	octx: crypto_hash_sha256_state;
}
declare var crypto_auth_hmacsha256_state: interop.StructType<crypto_auth_hmacsha256_state>;

declare function crypto_auth_hmacsha256_statebytes(): number;

declare function crypto_auth_hmacsha256_update(state: interop.Pointer | interop.Reference<crypto_auth_hmacsha256_state>, _in: string, inlen: number): number;

declare function crypto_auth_hmacsha256_verify(h: string, _in: string, inlen: number, k: string): number;

declare function crypto_auth_hmacsha512(out: string, _in: string, inlen: number, k: string): number;

declare function crypto_auth_hmacsha512256(out: string, _in: string, inlen: number, k: string): number;

declare function crypto_auth_hmacsha512256_bytes(): number;

declare function crypto_auth_hmacsha512256_final(state: interop.Pointer | interop.Reference<crypto_auth_hmacsha512_state>, out: string): number;

declare function crypto_auth_hmacsha512256_init(state: interop.Pointer | interop.Reference<crypto_auth_hmacsha512_state>, key: string, keylen: number): number;

declare function crypto_auth_hmacsha512256_keybytes(): number;

declare function crypto_auth_hmacsha512256_keygen(k: interop.Reference<number>): void;

declare function crypto_auth_hmacsha512256_statebytes(): number;

declare function crypto_auth_hmacsha512256_update(state: interop.Pointer | interop.Reference<crypto_auth_hmacsha512_state>, _in: string, inlen: number): number;

declare function crypto_auth_hmacsha512256_verify(h: string, _in: string, inlen: number, k: string): number;

declare function crypto_auth_hmacsha512_bytes(): number;

declare function crypto_auth_hmacsha512_final(state: interop.Pointer | interop.Reference<crypto_auth_hmacsha512_state>, out: string): number;

declare function crypto_auth_hmacsha512_init(state: interop.Pointer | interop.Reference<crypto_auth_hmacsha512_state>, key: string, keylen: number): number;

declare function crypto_auth_hmacsha512_keybytes(): number;

declare function crypto_auth_hmacsha512_keygen(k: interop.Reference<number>): void;

interface crypto_auth_hmacsha512_state {
	ictx: crypto_hash_sha512_state;
	octx: crypto_hash_sha512_state;
}
declare var crypto_auth_hmacsha512_state: interop.StructType<crypto_auth_hmacsha512_state>;

declare function crypto_auth_hmacsha512_statebytes(): number;

declare function crypto_auth_hmacsha512_update(state: interop.Pointer | interop.Reference<crypto_auth_hmacsha512_state>, _in: string, inlen: number): number;

declare function crypto_auth_hmacsha512_verify(h: string, _in: string, inlen: number, k: string): number;

declare function crypto_auth_keybytes(): number;

declare function crypto_auth_keygen(k: interop.Reference<number>): void;

declare function crypto_auth_primitive(): string;

declare function crypto_auth_verify(h: string, _in: string, inlen: number, k: string): number;

declare function crypto_box(c: string, m: string, mlen: number, n: string, pk: string, sk: string): number;

declare function crypto_box_afternm(c: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_box_beforenm(k: string, pk: string, sk: string): number;

declare function crypto_box_beforenmbytes(): number;

declare function crypto_box_boxzerobytes(): number;

declare function crypto_box_curve25519xchacha20poly1305_beforenm(k: string, pk: string, sk: string): number;

declare function crypto_box_curve25519xchacha20poly1305_beforenmbytes(): number;

declare function crypto_box_curve25519xchacha20poly1305_detached(c: string, mac: string, m: string, mlen: number, n: string, pk: string, sk: string): number;

declare function crypto_box_curve25519xchacha20poly1305_detached_afternm(c: string, mac: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_box_curve25519xchacha20poly1305_easy(c: string, m: string, mlen: number, n: string, pk: string, sk: string): number;

declare function crypto_box_curve25519xchacha20poly1305_easy_afternm(c: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_box_curve25519xchacha20poly1305_keypair(pk: string, sk: string): number;

declare function crypto_box_curve25519xchacha20poly1305_macbytes(): number;

declare function crypto_box_curve25519xchacha20poly1305_messagebytes_max(): number;

declare function crypto_box_curve25519xchacha20poly1305_noncebytes(): number;

declare function crypto_box_curve25519xchacha20poly1305_open_detached(m: string, c: string, mac: string, clen: number, n: string, pk: string, sk: string): number;

declare function crypto_box_curve25519xchacha20poly1305_open_detached_afternm(m: string, c: string, mac: string, clen: number, n: string, k: string): number;

declare function crypto_box_curve25519xchacha20poly1305_open_easy(m: string, c: string, clen: number, n: string, pk: string, sk: string): number;

declare function crypto_box_curve25519xchacha20poly1305_open_easy_afternm(m: string, c: string, clen: number, n: string, k: string): number;

declare function crypto_box_curve25519xchacha20poly1305_publickeybytes(): number;

declare function crypto_box_curve25519xchacha20poly1305_seal(c: string, m: string, mlen: number, pk: string): number;

declare function crypto_box_curve25519xchacha20poly1305_seal_open(m: string, c: string, clen: number, pk: string, sk: string): number;

declare function crypto_box_curve25519xchacha20poly1305_sealbytes(): number;

declare function crypto_box_curve25519xchacha20poly1305_secretkeybytes(): number;

declare function crypto_box_curve25519xchacha20poly1305_seed_keypair(pk: string, sk: string, seed: string): number;

declare function crypto_box_curve25519xchacha20poly1305_seedbytes(): number;

declare function crypto_box_curve25519xsalsa20poly1305(c: string, m: string, mlen: number, n: string, pk: string, sk: string): number;

declare function crypto_box_curve25519xsalsa20poly1305_afternm(c: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_box_curve25519xsalsa20poly1305_beforenm(k: string, pk: string, sk: string): number;

declare function crypto_box_curve25519xsalsa20poly1305_beforenmbytes(): number;

declare function crypto_box_curve25519xsalsa20poly1305_boxzerobytes(): number;

declare function crypto_box_curve25519xsalsa20poly1305_keypair(pk: string, sk: string): number;

declare function crypto_box_curve25519xsalsa20poly1305_macbytes(): number;

declare function crypto_box_curve25519xsalsa20poly1305_messagebytes_max(): number;

declare function crypto_box_curve25519xsalsa20poly1305_noncebytes(): number;

declare function crypto_box_curve25519xsalsa20poly1305_open(m: string, c: string, clen: number, n: string, pk: string, sk: string): number;

declare function crypto_box_curve25519xsalsa20poly1305_open_afternm(m: string, c: string, clen: number, n: string, k: string): number;

declare function crypto_box_curve25519xsalsa20poly1305_publickeybytes(): number;

declare function crypto_box_curve25519xsalsa20poly1305_secretkeybytes(): number;

declare function crypto_box_curve25519xsalsa20poly1305_seed_keypair(pk: string, sk: string, seed: string): number;

declare function crypto_box_curve25519xsalsa20poly1305_seedbytes(): number;

declare function crypto_box_curve25519xsalsa20poly1305_zerobytes(): number;

declare function crypto_box_detached(c: string, mac: string, m: string, mlen: number, n: string, pk: string, sk: string): number;

declare function crypto_box_detached_afternm(c: string, mac: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_box_easy(c: string, m: string, mlen: number, n: string, pk: string, sk: string): number;

declare function crypto_box_easy_afternm(c: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_box_keypair(pk: string, sk: string): number;

declare function crypto_box_macbytes(): number;

declare function crypto_box_messagebytes_max(): number;

declare function crypto_box_noncebytes(): number;

declare function crypto_box_open(m: string, c: string, clen: number, n: string, pk: string, sk: string): number;

declare function crypto_box_open_afternm(m: string, c: string, clen: number, n: string, k: string): number;

declare function crypto_box_open_detached(m: string, c: string, mac: string, clen: number, n: string, pk: string, sk: string): number;

declare function crypto_box_open_detached_afternm(m: string, c: string, mac: string, clen: number, n: string, k: string): number;

declare function crypto_box_open_easy(m: string, c: string, clen: number, n: string, pk: string, sk: string): number;

declare function crypto_box_open_easy_afternm(m: string, c: string, clen: number, n: string, k: string): number;

declare function crypto_box_primitive(): string;

declare function crypto_box_publickeybytes(): number;

declare function crypto_box_seal(c: string, m: string, mlen: number, pk: string): number;

declare function crypto_box_seal_open(m: string, c: string, clen: number, pk: string, sk: string): number;

declare function crypto_box_sealbytes(): number;

declare function crypto_box_secretkeybytes(): number;

declare function crypto_box_seed_keypair(pk: string, sk: string, seed: string): number;

declare function crypto_box_seedbytes(): number;

declare function crypto_box_zerobytes(): number;

declare function crypto_core_ed25519_add(r: string, p: string, q: string): number;

declare function crypto_core_ed25519_bytes(): number;

declare function crypto_core_ed25519_from_uniform(p: string, r: string): number;

declare function crypto_core_ed25519_is_valid_point(p: string): number;

declare function crypto_core_ed25519_nonreducedscalarbytes(): number;

declare function crypto_core_ed25519_scalar_add(z: string, x: string, y: string): void;

declare function crypto_core_ed25519_scalar_complement(comp: string, s: string): void;

declare function crypto_core_ed25519_scalar_invert(recip: string, s: string): number;

declare function crypto_core_ed25519_scalar_negate(neg: string, s: string): void;

declare function crypto_core_ed25519_scalar_random(r: string): void;

declare function crypto_core_ed25519_scalar_reduce(r: string, s: string): void;

declare function crypto_core_ed25519_scalar_sub(z: string, x: string, y: string): void;

declare function crypto_core_ed25519_scalarbytes(): number;

declare function crypto_core_ed25519_sub(r: string, p: string, q: string): number;

declare function crypto_core_ed25519_uniformbytes(): number;

declare function crypto_core_hchacha20(out: string, _in: string, k: string, c: string): number;

declare function crypto_core_hchacha20_constbytes(): number;

declare function crypto_core_hchacha20_inputbytes(): number;

declare function crypto_core_hchacha20_keybytes(): number;

declare function crypto_core_hchacha20_outputbytes(): number;

declare function crypto_core_hsalsa20(out: string, _in: string, k: string, c: string): number;

declare function crypto_core_hsalsa20_constbytes(): number;

declare function crypto_core_hsalsa20_inputbytes(): number;

declare function crypto_core_hsalsa20_keybytes(): number;

declare function crypto_core_hsalsa20_outputbytes(): number;

declare function crypto_core_salsa20(out: string, _in: string, k: string, c: string): number;

declare function crypto_core_salsa2012(out: string, _in: string, k: string, c: string): number;

declare function crypto_core_salsa2012_constbytes(): number;

declare function crypto_core_salsa2012_inputbytes(): number;

declare function crypto_core_salsa2012_keybytes(): number;

declare function crypto_core_salsa2012_outputbytes(): number;

declare function crypto_core_salsa208(out: string, _in: string, k: string, c: string): number;

declare function crypto_core_salsa208_constbytes(): number;

declare function crypto_core_salsa208_inputbytes(): number;

declare function crypto_core_salsa208_keybytes(): number;

declare function crypto_core_salsa208_outputbytes(): number;

declare function crypto_core_salsa20_constbytes(): number;

declare function crypto_core_salsa20_inputbytes(): number;

declare function crypto_core_salsa20_keybytes(): number;

declare function crypto_core_salsa20_outputbytes(): number;

declare function crypto_generichash(out: string, outlen: number, _in: string, inlen: number, key: string, keylen: number): number;

declare function crypto_generichash_blake2b(out: string, outlen: number, _in: string, inlen: number, key: string, keylen: number): number;

declare function crypto_generichash_blake2b_bytes(): number;

declare function crypto_generichash_blake2b_bytes_max(): number;

declare function crypto_generichash_blake2b_bytes_min(): number;

declare function crypto_generichash_blake2b_final(state: interop.Pointer | interop.Reference<crypto_generichash_blake2b_state>, out: string, outlen: number): number;

declare function crypto_generichash_blake2b_init(state: interop.Pointer | interop.Reference<crypto_generichash_blake2b_state>, key: string, keylen: number, outlen: number): number;

declare function crypto_generichash_blake2b_init_salt_personal(state: interop.Pointer | interop.Reference<crypto_generichash_blake2b_state>, key: string, keylen: number, outlen: number, salt: string, personal: string): number;

declare function crypto_generichash_blake2b_keybytes(): number;

declare function crypto_generichash_blake2b_keybytes_max(): number;

declare function crypto_generichash_blake2b_keybytes_min(): number;

declare function crypto_generichash_blake2b_keygen(k: interop.Reference<number>): void;

declare function crypto_generichash_blake2b_personalbytes(): number;

declare function crypto_generichash_blake2b_salt_personal(out: string, outlen: number, _in: string, inlen: number, key: string, keylen: number, salt: string, personal: string): number;

declare function crypto_generichash_blake2b_saltbytes(): number;

interface crypto_generichash_blake2b_state {
	opaque: interop.Reference<number>;
}
declare var crypto_generichash_blake2b_state: interop.StructType<crypto_generichash_blake2b_state>;

declare function crypto_generichash_blake2b_statebytes(): number;

declare function crypto_generichash_blake2b_update(state: interop.Pointer | interop.Reference<crypto_generichash_blake2b_state>, _in: string, inlen: number): number;

declare function crypto_generichash_bytes(): number;

declare function crypto_generichash_bytes_max(): number;

declare function crypto_generichash_bytes_min(): number;

declare function crypto_generichash_final(state: interop.Pointer | interop.Reference<crypto_generichash_blake2b_state>, out: string, outlen: number): number;

declare function crypto_generichash_init(state: interop.Pointer | interop.Reference<crypto_generichash_blake2b_state>, key: string, keylen: number, outlen: number): number;

declare function crypto_generichash_keybytes(): number;

declare function crypto_generichash_keybytes_max(): number;

declare function crypto_generichash_keybytes_min(): number;

declare function crypto_generichash_keygen(k: interop.Reference<number>): void;

declare function crypto_generichash_primitive(): string;

declare function crypto_generichash_statebytes(): number;

declare function crypto_generichash_update(state: interop.Pointer | interop.Reference<crypto_generichash_blake2b_state>, _in: string, inlen: number): number;

declare function crypto_hash(out: string, _in: string, inlen: number): number;

declare function crypto_hash_bytes(): number;

declare function crypto_hash_primitive(): string;

declare function crypto_hash_sha256(out: string, _in: string, inlen: number): number;

declare function crypto_hash_sha256_bytes(): number;

declare function crypto_hash_sha256_final(state: interop.Pointer | interop.Reference<crypto_hash_sha256_state>, out: string): number;

declare function crypto_hash_sha256_init(state: interop.Pointer | interop.Reference<crypto_hash_sha256_state>): number;

interface crypto_hash_sha256_state {
	state: interop.Reference<number>;
	count: number;
	buf: interop.Reference<number>;
}
declare var crypto_hash_sha256_state: interop.StructType<crypto_hash_sha256_state>;

declare function crypto_hash_sha256_statebytes(): number;

declare function crypto_hash_sha256_update(state: interop.Pointer | interop.Reference<crypto_hash_sha256_state>, _in: string, inlen: number): number;

declare function crypto_hash_sha512(out: string, _in: string, inlen: number): number;

declare function crypto_hash_sha512_bytes(): number;

declare function crypto_hash_sha512_final(state: interop.Pointer | interop.Reference<crypto_hash_sha512_state>, out: string): number;

declare function crypto_hash_sha512_init(state: interop.Pointer | interop.Reference<crypto_hash_sha512_state>): number;

interface crypto_hash_sha512_state {
	state: interop.Reference<number>;
	count: interop.Reference<number>;
	buf: interop.Reference<number>;
}
declare var crypto_hash_sha512_state: interop.StructType<crypto_hash_sha512_state>;

declare function crypto_hash_sha512_statebytes(): number;

declare function crypto_hash_sha512_update(state: interop.Pointer | interop.Reference<crypto_hash_sha512_state>, _in: string, inlen: number): number;

declare function crypto_kdf_blake2b_bytes_max(): number;

declare function crypto_kdf_blake2b_bytes_min(): number;

declare function crypto_kdf_blake2b_contextbytes(): number;

declare function crypto_kdf_blake2b_derive_from_key(subkey: string, subkey_len: number, subkey_id: number, ctx: interop.Reference<number>, key: interop.Reference<number>): number;

declare function crypto_kdf_blake2b_keybytes(): number;

declare function crypto_kdf_bytes_max(): number;

declare function crypto_kdf_bytes_min(): number;

declare function crypto_kdf_contextbytes(): number;

declare function crypto_kdf_derive_from_key(subkey: string, subkey_len: number, subkey_id: number, ctx: interop.Reference<number>, key: interop.Reference<number>): number;

declare function crypto_kdf_keybytes(): number;

declare function crypto_kdf_keygen(k: interop.Reference<number>): void;

declare function crypto_kdf_primitive(): string;

declare function crypto_kx_client_session_keys(rx: interop.Reference<number>, tx: interop.Reference<number>, client_pk: interop.Reference<number>, client_sk: interop.Reference<number>, server_pk: interop.Reference<number>): number;

declare function crypto_kx_keypair(pk: interop.Reference<number>, sk: interop.Reference<number>): number;

declare function crypto_kx_primitive(): string;

declare function crypto_kx_publickeybytes(): number;

declare function crypto_kx_secretkeybytes(): number;

declare function crypto_kx_seed_keypair(pk: interop.Reference<number>, sk: interop.Reference<number>, seed: interop.Reference<number>): number;

declare function crypto_kx_seedbytes(): number;

declare function crypto_kx_server_session_keys(rx: interop.Reference<number>, tx: interop.Reference<number>, server_pk: interop.Reference<number>, server_sk: interop.Reference<number>, client_pk: interop.Reference<number>): number;

declare function crypto_kx_sessionkeybytes(): number;

declare function crypto_onetimeauth(out: string, _in: string, inlen: number, k: string): number;

declare function crypto_onetimeauth_bytes(): number;

declare function crypto_onetimeauth_final(state: interop.Pointer | interop.Reference<crypto_onetimeauth_poly1305_state>, out: string): number;

declare function crypto_onetimeauth_init(state: interop.Pointer | interop.Reference<crypto_onetimeauth_poly1305_state>, key: string): number;

declare function crypto_onetimeauth_keybytes(): number;

declare function crypto_onetimeauth_keygen(k: interop.Reference<number>): void;

declare function crypto_onetimeauth_poly1305(out: string, _in: string, inlen: number, k: string): number;

declare function crypto_onetimeauth_poly1305_bytes(): number;

declare function crypto_onetimeauth_poly1305_final(state: interop.Pointer | interop.Reference<crypto_onetimeauth_poly1305_state>, out: string): number;

declare function crypto_onetimeauth_poly1305_init(state: interop.Pointer | interop.Reference<crypto_onetimeauth_poly1305_state>, key: string): number;

declare function crypto_onetimeauth_poly1305_keybytes(): number;

declare function crypto_onetimeauth_poly1305_keygen(k: interop.Reference<number>): void;

interface crypto_onetimeauth_poly1305_state {
	opaque: interop.Reference<number>;
}
declare var crypto_onetimeauth_poly1305_state: interop.StructType<crypto_onetimeauth_poly1305_state>;

declare function crypto_onetimeauth_poly1305_statebytes(): number;

declare function crypto_onetimeauth_poly1305_update(state: interop.Pointer | interop.Reference<crypto_onetimeauth_poly1305_state>, _in: string, inlen: number): number;

declare function crypto_onetimeauth_poly1305_verify(h: string, _in: string, inlen: number, k: string): number;

declare function crypto_onetimeauth_primitive(): string;

declare function crypto_onetimeauth_statebytes(): number;

declare function crypto_onetimeauth_update(state: interop.Pointer | interop.Reference<crypto_onetimeauth_poly1305_state>, _in: string, inlen: number): number;

declare function crypto_onetimeauth_verify(h: string, _in: string, inlen: number, k: string): number;

declare function crypto_pwhash(out: string, outlen: number, passwd: string, passwdlen: number, salt: string, opslimit: number, memlimit: number, alg: number): number;

declare function crypto_pwhash_alg_argon2i13(): number;

declare function crypto_pwhash_alg_argon2id13(): number;

declare function crypto_pwhash_alg_default(): number;

declare function crypto_pwhash_argon2i(out: string, outlen: number, passwd: string, passwdlen: number, salt: string, opslimit: number, memlimit: number, alg: number): number;

declare function crypto_pwhash_argon2i_alg_argon2i13(): number;

declare function crypto_pwhash_argon2i_bytes_max(): number;

declare function crypto_pwhash_argon2i_bytes_min(): number;

declare function crypto_pwhash_argon2i_memlimit_interactive(): number;

declare function crypto_pwhash_argon2i_memlimit_max(): number;

declare function crypto_pwhash_argon2i_memlimit_min(): number;

declare function crypto_pwhash_argon2i_memlimit_moderate(): number;

declare function crypto_pwhash_argon2i_memlimit_sensitive(): number;

declare function crypto_pwhash_argon2i_opslimit_interactive(): number;

declare function crypto_pwhash_argon2i_opslimit_max(): number;

declare function crypto_pwhash_argon2i_opslimit_min(): number;

declare function crypto_pwhash_argon2i_opslimit_moderate(): number;

declare function crypto_pwhash_argon2i_opslimit_sensitive(): number;

declare function crypto_pwhash_argon2i_passwd_max(): number;

declare function crypto_pwhash_argon2i_passwd_min(): number;

declare function crypto_pwhash_argon2i_saltbytes(): number;

declare function crypto_pwhash_argon2i_str(out: interop.Reference<number>, passwd: string, passwdlen: number, opslimit: number, memlimit: number): number;

declare function crypto_pwhash_argon2i_str_needs_rehash(str: interop.Reference<number>, opslimit: number, memlimit: number): number;

declare function crypto_pwhash_argon2i_str_verify(str: interop.Reference<number>, passwd: string, passwdlen: number): number;

declare function crypto_pwhash_argon2i_strbytes(): number;

declare function crypto_pwhash_argon2i_strprefix(): string;

declare function crypto_pwhash_argon2id(out: string, outlen: number, passwd: string, passwdlen: number, salt: string, opslimit: number, memlimit: number, alg: number): number;

declare function crypto_pwhash_argon2id_alg_argon2id13(): number;

declare function crypto_pwhash_argon2id_bytes_max(): number;

declare function crypto_pwhash_argon2id_bytes_min(): number;

declare function crypto_pwhash_argon2id_memlimit_interactive(): number;

declare function crypto_pwhash_argon2id_memlimit_max(): number;

declare function crypto_pwhash_argon2id_memlimit_min(): number;

declare function crypto_pwhash_argon2id_memlimit_moderate(): number;

declare function crypto_pwhash_argon2id_memlimit_sensitive(): number;

declare function crypto_pwhash_argon2id_opslimit_interactive(): number;

declare function crypto_pwhash_argon2id_opslimit_max(): number;

declare function crypto_pwhash_argon2id_opslimit_min(): number;

declare function crypto_pwhash_argon2id_opslimit_moderate(): number;

declare function crypto_pwhash_argon2id_opslimit_sensitive(): number;

declare function crypto_pwhash_argon2id_passwd_max(): number;

declare function crypto_pwhash_argon2id_passwd_min(): number;

declare function crypto_pwhash_argon2id_saltbytes(): number;

declare function crypto_pwhash_argon2id_str(out: interop.Reference<number>, passwd: string, passwdlen: number, opslimit: number, memlimit: number): number;

declare function crypto_pwhash_argon2id_str_needs_rehash(str: interop.Reference<number>, opslimit: number, memlimit: number): number;

declare function crypto_pwhash_argon2id_str_verify(str: interop.Reference<number>, passwd: string, passwdlen: number): number;

declare function crypto_pwhash_argon2id_strbytes(): number;

declare function crypto_pwhash_argon2id_strprefix(): string;

declare function crypto_pwhash_bytes_max(): number;

declare function crypto_pwhash_bytes_min(): number;

declare function crypto_pwhash_memlimit_interactive(): number;

declare function crypto_pwhash_memlimit_max(): number;

declare function crypto_pwhash_memlimit_min(): number;

declare function crypto_pwhash_memlimit_moderate(): number;

declare function crypto_pwhash_memlimit_sensitive(): number;

declare function crypto_pwhash_opslimit_interactive(): number;

declare function crypto_pwhash_opslimit_max(): number;

declare function crypto_pwhash_opslimit_min(): number;

declare function crypto_pwhash_opslimit_moderate(): number;

declare function crypto_pwhash_opslimit_sensitive(): number;

declare function crypto_pwhash_passwd_max(): number;

declare function crypto_pwhash_passwd_min(): number;

declare function crypto_pwhash_primitive(): string;

declare function crypto_pwhash_saltbytes(): number;

declare function crypto_pwhash_scryptsalsa208sha256(out: string, outlen: number, passwd: string, passwdlen: number, salt: string, opslimit: number, memlimit: number): number;

declare function crypto_pwhash_scryptsalsa208sha256_bytes_max(): number;

declare function crypto_pwhash_scryptsalsa208sha256_bytes_min(): number;

declare function crypto_pwhash_scryptsalsa208sha256_ll(passwd: string, passwdlen: number, salt: string, saltlen: number, N: number, r: number, p: number, buf: string, buflen: number): number;

declare function crypto_pwhash_scryptsalsa208sha256_memlimit_interactive(): number;

declare function crypto_pwhash_scryptsalsa208sha256_memlimit_max(): number;

declare function crypto_pwhash_scryptsalsa208sha256_memlimit_min(): number;

declare function crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive(): number;

declare function crypto_pwhash_scryptsalsa208sha256_opslimit_interactive(): number;

declare function crypto_pwhash_scryptsalsa208sha256_opslimit_max(): number;

declare function crypto_pwhash_scryptsalsa208sha256_opslimit_min(): number;

declare function crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive(): number;

declare function crypto_pwhash_scryptsalsa208sha256_passwd_max(): number;

declare function crypto_pwhash_scryptsalsa208sha256_passwd_min(): number;

declare function crypto_pwhash_scryptsalsa208sha256_saltbytes(): number;

declare function crypto_pwhash_scryptsalsa208sha256_str(out: interop.Reference<number>, passwd: string, passwdlen: number, opslimit: number, memlimit: number): number;

declare function crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(str: interop.Reference<number>, opslimit: number, memlimit: number): number;

declare function crypto_pwhash_scryptsalsa208sha256_str_verify(str: interop.Reference<number>, passwd: string, passwdlen: number): number;

declare function crypto_pwhash_scryptsalsa208sha256_strbytes(): number;

declare function crypto_pwhash_scryptsalsa208sha256_strprefix(): string;

declare function crypto_pwhash_str(out: interop.Reference<number>, passwd: string, passwdlen: number, opslimit: number, memlimit: number): number;

declare function crypto_pwhash_str_alg(out: interop.Reference<number>, passwd: string, passwdlen: number, opslimit: number, memlimit: number, alg: number): number;

declare function crypto_pwhash_str_needs_rehash(str: interop.Reference<number>, opslimit: number, memlimit: number): number;

declare function crypto_pwhash_str_verify(str: interop.Reference<number>, passwd: string, passwdlen: number): number;

declare function crypto_pwhash_strbytes(): number;

declare function crypto_pwhash_strprefix(): string;

declare function crypto_scalarmult(q: string, n: string, p: string): number;

declare function crypto_scalarmult_base(q: string, n: string): number;

declare function crypto_scalarmult_bytes(): number;

declare function crypto_scalarmult_curve25519(q: string, n: string, p: string): number;

declare function crypto_scalarmult_curve25519_base(q: string, n: string): number;

declare function crypto_scalarmult_curve25519_bytes(): number;

declare function crypto_scalarmult_curve25519_scalarbytes(): number;

declare function crypto_scalarmult_ed25519(q: string, n: string, p: string): number;

declare function crypto_scalarmult_ed25519_base(q: string, n: string): number;

declare function crypto_scalarmult_ed25519_base_noclamp(q: string, n: string): number;

declare function crypto_scalarmult_ed25519_bytes(): number;

declare function crypto_scalarmult_ed25519_noclamp(q: string, n: string, p: string): number;

declare function crypto_scalarmult_ed25519_scalarbytes(): number;

declare function crypto_scalarmult_primitive(): string;

declare function crypto_scalarmult_scalarbytes(): number;

declare function crypto_secretbox(c: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_secretbox_boxzerobytes(): number;

declare function crypto_secretbox_detached(c: string, mac: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_secretbox_easy(c: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_secretbox_keybytes(): number;

declare function crypto_secretbox_keygen(k: interop.Reference<number>): void;

declare function crypto_secretbox_macbytes(): number;

declare function crypto_secretbox_messagebytes_max(): number;

declare function crypto_secretbox_noncebytes(): number;

declare function crypto_secretbox_open(m: string, c: string, clen: number, n: string, k: string): number;

declare function crypto_secretbox_open_detached(m: string, c: string, mac: string, clen: number, n: string, k: string): number;

declare function crypto_secretbox_open_easy(m: string, c: string, clen: number, n: string, k: string): number;

declare function crypto_secretbox_primitive(): string;

declare function crypto_secretbox_xchacha20poly1305_detached(c: string, mac: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_secretbox_xchacha20poly1305_easy(c: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_secretbox_xchacha20poly1305_keybytes(): number;

declare function crypto_secretbox_xchacha20poly1305_macbytes(): number;

declare function crypto_secretbox_xchacha20poly1305_messagebytes_max(): number;

declare function crypto_secretbox_xchacha20poly1305_noncebytes(): number;

declare function crypto_secretbox_xchacha20poly1305_open_detached(m: string, c: string, mac: string, clen: number, n: string, k: string): number;

declare function crypto_secretbox_xchacha20poly1305_open_easy(m: string, c: string, clen: number, n: string, k: string): number;

declare function crypto_secretbox_xsalsa20poly1305(c: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_secretbox_xsalsa20poly1305_boxzerobytes(): number;

declare function crypto_secretbox_xsalsa20poly1305_keybytes(): number;

declare function crypto_secretbox_xsalsa20poly1305_keygen(k: interop.Reference<number>): void;

declare function crypto_secretbox_xsalsa20poly1305_macbytes(): number;

declare function crypto_secretbox_xsalsa20poly1305_messagebytes_max(): number;

declare function crypto_secretbox_xsalsa20poly1305_noncebytes(): number;

declare function crypto_secretbox_xsalsa20poly1305_open(m: string, c: string, clen: number, n: string, k: string): number;

declare function crypto_secretbox_xsalsa20poly1305_zerobytes(): number;

declare function crypto_secretbox_zerobytes(): number;

declare function crypto_secretstream_xchacha20poly1305_abytes(): number;

declare function crypto_secretstream_xchacha20poly1305_headerbytes(): number;

declare function crypto_secretstream_xchacha20poly1305_init_pull(state: interop.Pointer | interop.Reference<crypto_secretstream_xchacha20poly1305_state>, header: interop.Reference<number>, k: interop.Reference<number>): number;

declare function crypto_secretstream_xchacha20poly1305_init_push(state: interop.Pointer | interop.Reference<crypto_secretstream_xchacha20poly1305_state>, header: interop.Reference<number>, k: interop.Reference<number>): number;

declare function crypto_secretstream_xchacha20poly1305_keybytes(): number;

declare function crypto_secretstream_xchacha20poly1305_keygen(k: interop.Reference<number>): void;

declare function crypto_secretstream_xchacha20poly1305_messagebytes_max(): number;

declare function crypto_secretstream_xchacha20poly1305_pull(state: interop.Pointer | interop.Reference<crypto_secretstream_xchacha20poly1305_state>, m: string, mlen_p: interop.Pointer | interop.Reference<number>, tag_p: string, c: string, clen: number, ad: string, adlen: number): number;

declare function crypto_secretstream_xchacha20poly1305_push(state: interop.Pointer | interop.Reference<crypto_secretstream_xchacha20poly1305_state>, c: string, clen_p: interop.Pointer | interop.Reference<number>, m: string, mlen: number, ad: string, adlen: number, tag: number): number;

declare function crypto_secretstream_xchacha20poly1305_rekey(state: interop.Pointer | interop.Reference<crypto_secretstream_xchacha20poly1305_state>): void;

interface crypto_secretstream_xchacha20poly1305_state {
	k: interop.Reference<number>;
	nonce: interop.Reference<number>;
	_pad: interop.Reference<number>;
}
declare var crypto_secretstream_xchacha20poly1305_state: interop.StructType<crypto_secretstream_xchacha20poly1305_state>;

declare function crypto_secretstream_xchacha20poly1305_statebytes(): number;

declare function crypto_secretstream_xchacha20poly1305_tag_final(): number;

declare function crypto_secretstream_xchacha20poly1305_tag_message(): number;

declare function crypto_secretstream_xchacha20poly1305_tag_push(): number;

declare function crypto_secretstream_xchacha20poly1305_tag_rekey(): number;

declare function crypto_shorthash(out: string, _in: string, inlen: number, k: string): number;

declare function crypto_shorthash_bytes(): number;

declare function crypto_shorthash_keybytes(): number;

declare function crypto_shorthash_keygen(k: interop.Reference<number>): void;

declare function crypto_shorthash_primitive(): string;

declare function crypto_shorthash_siphash24(out: string, _in: string, inlen: number, k: string): number;

declare function crypto_shorthash_siphash24_bytes(): number;

declare function crypto_shorthash_siphash24_keybytes(): number;

declare function crypto_shorthash_siphashx24(out: string, _in: string, inlen: number, k: string): number;

declare function crypto_shorthash_siphashx24_bytes(): number;

declare function crypto_shorthash_siphashx24_keybytes(): number;

declare function crypto_sign(sm: string, smlen_p: interop.Pointer | interop.Reference<number>, m: string, mlen: number, sk: string): number;

declare function crypto_sign_bytes(): number;

declare function crypto_sign_detached(sig: string, siglen_p: interop.Pointer | interop.Reference<number>, m: string, mlen: number, sk: string): number;

declare function crypto_sign_ed25519(sm: string, smlen_p: interop.Pointer | interop.Reference<number>, m: string, mlen: number, sk: string): number;

declare function crypto_sign_ed25519_bytes(): number;

declare function crypto_sign_ed25519_detached(sig: string, siglen_p: interop.Pointer | interop.Reference<number>, m: string, mlen: number, sk: string): number;

declare function crypto_sign_ed25519_keypair(pk: string, sk: string): number;

declare function crypto_sign_ed25519_messagebytes_max(): number;

declare function crypto_sign_ed25519_open(m: string, mlen_p: interop.Pointer | interop.Reference<number>, sm: string, smlen: number, pk: string): number;

declare function crypto_sign_ed25519_pk_to_curve25519(curve25519_pk: string, ed25519_pk: string): number;

declare function crypto_sign_ed25519_publickeybytes(): number;

declare function crypto_sign_ed25519_secretkeybytes(): number;

declare function crypto_sign_ed25519_seed_keypair(pk: string, sk: string, seed: string): number;

declare function crypto_sign_ed25519_seedbytes(): number;

declare function crypto_sign_ed25519_sk_to_curve25519(curve25519_sk: string, ed25519_sk: string): number;

declare function crypto_sign_ed25519_sk_to_pk(pk: string, sk: string): number;

declare function crypto_sign_ed25519_sk_to_seed(seed: string, sk: string): number;

declare function crypto_sign_ed25519_verify_detached(sig: string, m: string, mlen: number, pk: string): number;

declare function crypto_sign_ed25519ph_final_create(state: interop.Pointer | interop.Reference<crypto_sign_ed25519ph_state>, sig: string, siglen_p: interop.Pointer | interop.Reference<number>, sk: string): number;

declare function crypto_sign_ed25519ph_final_verify(state: interop.Pointer | interop.Reference<crypto_sign_ed25519ph_state>, sig: string, pk: string): number;

declare function crypto_sign_ed25519ph_init(state: interop.Pointer | interop.Reference<crypto_sign_ed25519ph_state>): number;

interface crypto_sign_ed25519ph_state {
	hs: crypto_hash_sha512_state;
}
declare var crypto_sign_ed25519ph_state: interop.StructType<crypto_sign_ed25519ph_state>;

declare function crypto_sign_ed25519ph_statebytes(): number;

declare function crypto_sign_ed25519ph_update(state: interop.Pointer | interop.Reference<crypto_sign_ed25519ph_state>, m: string, mlen: number): number;

declare function crypto_sign_edwards25519sha512batch(sm: string, smlen_p: interop.Pointer | interop.Reference<number>, m: string, mlen: number, sk: string): number;

declare function crypto_sign_edwards25519sha512batch_keypair(pk: string, sk: string): number;

declare function crypto_sign_edwards25519sha512batch_open(m: string, mlen_p: interop.Pointer | interop.Reference<number>, sm: string, smlen: number, pk: string): number;

declare function crypto_sign_final_create(state: interop.Pointer | interop.Reference<crypto_sign_ed25519ph_state>, sig: string, siglen_p: interop.Pointer | interop.Reference<number>, sk: string): number;

declare function crypto_sign_final_verify(state: interop.Pointer | interop.Reference<crypto_sign_ed25519ph_state>, sig: string, pk: string): number;

declare function crypto_sign_init(state: interop.Pointer | interop.Reference<crypto_sign_ed25519ph_state>): number;

declare function crypto_sign_keypair(pk: string, sk: string): number;

declare function crypto_sign_messagebytes_max(): number;

declare function crypto_sign_open(m: string, mlen_p: interop.Pointer | interop.Reference<number>, sm: string, smlen: number, pk: string): number;

declare function crypto_sign_primitive(): string;

declare function crypto_sign_publickeybytes(): number;

declare function crypto_sign_secretkeybytes(): number;

declare function crypto_sign_seed_keypair(pk: string, sk: string, seed: string): number;

declare function crypto_sign_seedbytes(): number;

declare function crypto_sign_statebytes(): number;

declare function crypto_sign_update(state: interop.Pointer | interop.Reference<crypto_sign_ed25519ph_state>, m: string, mlen: number): number;

declare function crypto_sign_verify_detached(sig: string, m: string, mlen: number, pk: string): number;

declare function crypto_stream(c: string, clen: number, n: string, k: string): number;

declare function crypto_stream_chacha20(c: string, clen: number, n: string, k: string): number;

declare function crypto_stream_chacha20_ietf(c: string, clen: number, n: string, k: string): number;

declare function crypto_stream_chacha20_ietf_keybytes(): number;

declare function crypto_stream_chacha20_ietf_keygen(k: interop.Reference<number>): void;

declare function crypto_stream_chacha20_ietf_messagebytes_max(): number;

declare function crypto_stream_chacha20_ietf_noncebytes(): number;

declare function crypto_stream_chacha20_ietf_xor(c: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_stream_chacha20_ietf_xor_ic(c: string, m: string, mlen: number, n: string, ic: number, k: string): number;

declare function crypto_stream_chacha20_keybytes(): number;

declare function crypto_stream_chacha20_keygen(k: interop.Reference<number>): void;

declare function crypto_stream_chacha20_messagebytes_max(): number;

declare function crypto_stream_chacha20_noncebytes(): number;

declare function crypto_stream_chacha20_xor(c: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_stream_chacha20_xor_ic(c: string, m: string, mlen: number, n: string, ic: number, k: string): number;

declare function crypto_stream_keybytes(): number;

declare function crypto_stream_keygen(k: interop.Reference<number>): void;

declare function crypto_stream_messagebytes_max(): number;

declare function crypto_stream_noncebytes(): number;

declare function crypto_stream_primitive(): string;

declare function crypto_stream_salsa20(c: string, clen: number, n: string, k: string): number;

declare function crypto_stream_salsa2012(c: string, clen: number, n: string, k: string): number;

declare function crypto_stream_salsa2012_keybytes(): number;

declare function crypto_stream_salsa2012_keygen(k: interop.Reference<number>): void;

declare function crypto_stream_salsa2012_messagebytes_max(): number;

declare function crypto_stream_salsa2012_noncebytes(): number;

declare function crypto_stream_salsa2012_xor(c: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_stream_salsa208(c: string, clen: number, n: string, k: string): number;

declare function crypto_stream_salsa208_keybytes(): number;

declare function crypto_stream_salsa208_keygen(k: interop.Reference<number>): void;

declare function crypto_stream_salsa208_messagebytes_max(): number;

declare function crypto_stream_salsa208_noncebytes(): number;

declare function crypto_stream_salsa208_xor(c: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_stream_salsa20_keybytes(): number;

declare function crypto_stream_salsa20_keygen(k: interop.Reference<number>): void;

declare function crypto_stream_salsa20_messagebytes_max(): number;

declare function crypto_stream_salsa20_noncebytes(): number;

declare function crypto_stream_salsa20_xor(c: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_stream_salsa20_xor_ic(c: string, m: string, mlen: number, n: string, ic: number, k: string): number;

declare function crypto_stream_xchacha20(c: string, clen: number, n: string, k: string): number;

declare function crypto_stream_xchacha20_keybytes(): number;

declare function crypto_stream_xchacha20_keygen(k: interop.Reference<number>): void;

declare function crypto_stream_xchacha20_messagebytes_max(): number;

declare function crypto_stream_xchacha20_noncebytes(): number;

declare function crypto_stream_xchacha20_xor(c: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_stream_xchacha20_xor_ic(c: string, m: string, mlen: number, n: string, ic: number, k: string): number;

declare function crypto_stream_xor(c: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_stream_xsalsa20(c: string, clen: number, n: string, k: string): number;

declare function crypto_stream_xsalsa20_keybytes(): number;

declare function crypto_stream_xsalsa20_keygen(k: interop.Reference<number>): void;

declare function crypto_stream_xsalsa20_messagebytes_max(): number;

declare function crypto_stream_xsalsa20_noncebytes(): number;

declare function crypto_stream_xsalsa20_xor(c: string, m: string, mlen: number, n: string, k: string): number;

declare function crypto_stream_xsalsa20_xor_ic(c: string, m: string, mlen: number, n: string, ic: number, k: string): number;

declare function crypto_verify_16(x: string, y: string): number;

declare function crypto_verify_16_bytes(): number;

declare function crypto_verify_32(x: string, y: string): number;

declare function crypto_verify_32_bytes(): number;

declare function crypto_verify_64(x: string, y: string): number;

declare function crypto_verify_64_bytes(): number;

declare function randombytes(buf: string, buf_len: number): void;

declare function randombytes_buf(buf: interop.Pointer | interop.Reference<any>, size: number): void;

declare function randombytes_buf_deterministic(buf: interop.Pointer | interop.Reference<any>, size: number, seed: interop.Reference<number>): void;

declare function randombytes_close(): number;

interface randombytes_implementation {
	implementation_name: interop.FunctionReference<() => string>;
	random: interop.FunctionReference<() => number>;
	stir: interop.FunctionReference<() => void>;
	uniform: interop.FunctionReference<(p1: number) => number>;
	buf: interop.FunctionReference<(p1: interop.Pointer | interop.Reference<any>, p2: number) => void>;
	close: interop.FunctionReference<() => number>;
}
declare var randombytes_implementation: interop.StructType<randombytes_implementation>;

declare function randombytes_implementation_name(): string;

declare function randombytes_random(): number;

declare var randombytes_salsa20_implementation: randombytes_implementation;

declare function randombytes_seedbytes(): number;

declare function randombytes_set_implementation(impl: interop.Pointer | interop.Reference<randombytes_implementation>): number;

declare function randombytes_stir(): void;

declare var randombytes_sysrandom_implementation: randombytes_implementation;

declare function randombytes_uniform(upper_bound: number): number;

declare function sodium_add(a: string, b: string, len: number): void;

declare function sodium_allocarray(count: number, size: number): interop.Pointer | interop.Reference<any>;

declare function sodium_base642bin(bin: string, bin_maxlen: number, b64: string, b64_len: number, ignore: string, bin_len: interop.Pointer | interop.Reference<number>, b64_end: interop.Pointer | interop.Reference<string>, variant: number): number;

declare function sodium_base64_encoded_len(bin_len: number, variant: number): number;

declare function sodium_bin2base64(b64: string, b64_maxlen: number, bin: string, bin_len: number, variant: number): string;

declare function sodium_bin2hex(hex: string, hex_maxlen: number, bin: string, bin_len: number): string;

declare function sodium_compare(b1_: string, b2_: string, len: number): number;

declare function sodium_free(ptr: interop.Pointer | interop.Reference<any>): void;

declare function sodium_hex2bin(bin: string, bin_maxlen: number, hex: string, hex_len: number, ignore: string, bin_len: interop.Pointer | interop.Reference<number>, hex_end: interop.Pointer | interop.Reference<string>): number;

declare function sodium_increment(n: string, nlen: number): void;

declare function sodium_init(): number;

declare function sodium_is_zero(n: string, nlen: number): number;

declare function sodium_library_minimal(): number;

declare function sodium_library_version_major(): number;

declare function sodium_library_version_minor(): number;

declare function sodium_malloc(size: number): interop.Pointer | interop.Reference<any>;

declare function sodium_memcmp(b1_: interop.Pointer | interop.Reference<any>, b2_: interop.Pointer | interop.Reference<any>, len: number): number;

declare function sodium_memzero(pnt: interop.Pointer | interop.Reference<any>, len: number): void;

declare function sodium_misuse(): void;

declare function sodium_mlock(addr: interop.Pointer | interop.Reference<any>, len: number): number;

declare function sodium_mprotect_noaccess(ptr: interop.Pointer | interop.Reference<any>): number;

declare function sodium_mprotect_readonly(ptr: interop.Pointer | interop.Reference<any>): number;

declare function sodium_mprotect_readwrite(ptr: interop.Pointer | interop.Reference<any>): number;

declare function sodium_munlock(addr: interop.Pointer | interop.Reference<any>, len: number): number;

declare function sodium_pad(padded_buflen_p: interop.Pointer | interop.Reference<number>, buf: string, unpadded_buflen: number, blocksize: number, max_buflen: number): number;

declare function sodium_runtime_has_aesni(): number;

declare function sodium_runtime_has_avx(): number;

declare function sodium_runtime_has_avx2(): number;

declare function sodium_runtime_has_avx512f(): number;

declare function sodium_runtime_has_neon(): number;

declare function sodium_runtime_has_pclmul(): number;

declare function sodium_runtime_has_rdrand(): number;

declare function sodium_runtime_has_sse2(): number;

declare function sodium_runtime_has_sse3(): number;

declare function sodium_runtime_has_sse41(): number;

declare function sodium_runtime_has_ssse3(): number;

declare function sodium_set_misuse_handler(handler: interop.FunctionReference<() => void>): number;

declare function sodium_stackzero(len: number): void;

declare function sodium_sub(a: string, b: string, len: number): void;

declare function sodium_unpad(unpadded_buflen_p: interop.Pointer | interop.Reference<number>, buf: string, padded_buflen: number, blocksize: number): number;

declare function sodium_version_string(): string;
