/// <reference path="android-declarations.d.ts"/>

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export class BuildConfig {
					public static class: java.lang.Class<com.goterl.lazycode.lazysodium.BuildConfig>;
					public static DEBUG: boolean;
					public static APPLICATION_ID: string;
					public static BUILD_TYPE: string;
					public static FLAVOR: string;
					public static VERSION_CODE: number;
					public static VERSION_NAME: string;
					public constructor();
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export abstract class LazySodium implements com.goterl.lazycode.lazysodium.interfaces.Base, com.goterl.lazycode.lazysodium.interfaces.Random, com.goterl.lazycode.lazysodium.interfaces.AEAD.Native, com.goterl.lazycode.lazysodium.interfaces.AEAD.Lazy, com.goterl.lazycode.lazysodium.interfaces.GenericHash.Native, com.goterl.lazycode.lazysodium.interfaces.GenericHash.Lazy, com.goterl.lazycode.lazysodium.interfaces.ShortHash.Native, com.goterl.lazycode.lazysodium.interfaces.ShortHash.Lazy, com.goterl.lazycode.lazysodium.interfaces.SecureMemory.Native, com.goterl.lazycode.lazysodium.interfaces.SecureMemory.Lazy, com.goterl.lazycode.lazysodium.interfaces.Auth.Native, com.goterl.lazycode.lazysodium.interfaces.Auth.Lazy, com.goterl.lazycode.lazysodium.interfaces.SecretStream.Native, com.goterl.lazycode.lazysodium.interfaces.SecretStream.Lazy, com.goterl.lazycode.lazysodium.interfaces.Stream.Native, com.goterl.lazycode.lazysodium.interfaces.Stream.Lazy, com.goterl.lazycode.lazysodium.interfaces.Padding.Native, com.goterl.lazycode.lazysodium.interfaces.Padding.Lazy, com.goterl.lazycode.lazysodium.interfaces.Helpers.Native, com.goterl.lazycode.lazysodium.interfaces.Helpers.Lazy, com.goterl.lazycode.lazysodium.interfaces.PwHash.Native, com.goterl.lazycode.lazysodium.interfaces.PwHash.Lazy, com.goterl.lazycode.lazysodium.interfaces.Hash.Native, com.goterl.lazycode.lazysodium.interfaces.Hash.Lazy, com.goterl.lazycode.lazysodium.interfaces.Sign.Native, com.goterl.lazycode.lazysodium.interfaces.Sign.Lazy, com.goterl.lazycode.lazysodium.interfaces.Box.Native, com.goterl.lazycode.lazysodium.interfaces.Box.Lazy, com.goterl.lazycode.lazysodium.interfaces.SecretBox.Native, com.goterl.lazycode.lazysodium.interfaces.SecretBox.Lazy, com.goterl.lazycode.lazysodium.interfaces.KeyExchange.Native, com.goterl.lazycode.lazysodium.interfaces.KeyExchange.Lazy, com.goterl.lazycode.lazysodium.interfaces.KeyDerivation.Native, com.goterl.lazycode.lazysodium.interfaces.KeyDerivation.Lazy, com.goterl.lazycode.lazysodium.interfaces.DiffieHellman.Native, com.goterl.lazycode.lazysodium.interfaces.DiffieHellman.Lazy {
					public static class: java.lang.Class<com.goterl.lazycode.lazysodium.LazySodium>;
					public charset: java.nio.charset.Charset;
					public successful(param0: number): boolean;
					public sodiumAllocArray(param0: number, param1: number): com.sun.jna.Pointer;
					public decrypt(param0: string, param1: string, param2: native.Array<number>, param3: native.Array<number>, param4: com.goterl.lazycode.lazysodium.utils.Key, param5: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): string;
					public cryptoSecretStreamRekey(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State): void;
					public cryptoGenericHash(param0: string): string;
					public cryptoGenericHash(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number): boolean;
					public cryptoSecretStreamPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: string, param2: number): string;
					public cryptoBoxSeedKeypair(param0: native.Array<number>): com.goterl.lazycode.lazysodium.utils.KeyPair;
					public cryptoShortHash(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public constructor();
					public cryptoAeadChaCha20Poly1305Encrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public encrypt(param0: string, param1: string, param2: native.Array<number>, param3: native.Array<number>, param4: com.goterl.lazycode.lazysodium.utils.Key, param5: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): string;
					public cryptoAuthKeygen(param0: native.Array<number>): void;
					public cryptoAeadChaCha20Poly1305Decrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoAuthHMACSha512Keygen(param0: native.Array<number>): void;
					public wrongLen(param0: number, param1: number): boolean;
					public cryptoPwHash(param0: string, param1: number, param2: native.Array<number>, param3: number, param4: com.sun.jna.NativeLong, param5: com.goterl.lazycode.lazysodium.interfaces.PwHash.Alg): string;
					public cryptoSecretStreamPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: number): boolean;
					public encrypt(param0: string, param1: string, param2: native.Array<number>, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): string;
					public cryptoKxServerSessionKeys(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoShortHash(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
					public static toBin(param0: string): native.Array<number>;
					public cryptoShortHashKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoAuth(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public sodiumMLock(param0: native.Array<number>, param1: number): boolean;
					public cryptoSecretStreamPull(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number): boolean;
					public cryptoStreamXor(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key, param3: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
					public cryptoSecretStreamPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: number): boolean;
					public randomBytesRandom(): number;
					public cryptoBoxSealOpen(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoSign(param0: string, param1: string): string;
					public cryptoAeadChaCha20Poly1305DecryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoAeadChaCha20Poly1305IetfDecrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoBoxEasyAfterNm(param0: string, param1: native.Array<number>, param2: string): string;
					public cryptoGenericHashInit(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: number): boolean;
					public cryptoScalarMult(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
					public keygen(param0: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoStreamChaCha20IetfXor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoSecretStreamInitPull(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>): boolean;
					public sodiumMProtectNoAccess(param0: com.sun.jna.Pointer): boolean;
					public cryptoBoxEasy(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.KeyPair): string;
					public cryptoBoxOpenDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>, param5: native.Array<number>, param6: native.Array<number>): boolean;
					public sodiumPad(param0: number, param1: native.Array<string>, param2: number, param3: number, param4: number): boolean;
					public cryptoAuthHMACShaUpdate(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: string): boolean;
					public cryptoHashSha512Update(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512, param1: string): boolean;
					public cryptoAuthHMACSha256Init(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: native.Array<number>, param2: number): boolean;
					public sodiumInit(): number;
					public cryptoAeadAES256GCMEncryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): boolean;
					public cryptoStream(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): native.Array<number>;
					public cryptoAuthHMACSha512Update(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: native.Array<number>, param2: number): boolean;
					public cryptoAuthHMACSha256(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public cryptoAeadChaCha20Poly1305IetfDecryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoScalarMult(param0: com.goterl.lazycode.lazysodium.utils.Key, param1: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoSignDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>): boolean;
					public cryptoAeadAES256GCMIsAvailable(): boolean;
					public sodiumUnpad(param0: number, param1: native.Array<string>, param2: number, param3: number): boolean;
					public str(param0: native.Array<number>): string;
					public cryptoAuthHMACSha256Update(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: native.Array<number>, param2: number): boolean;
					public cryptoBoxKeypair(): com.goterl.lazycode.lazysodium.utils.KeyPair;
					public cryptoAuthHMACSha256Verify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public cryptoStreamXorDecrypt(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key, param3: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
					public cryptoAuth(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
					public cryptoKdfKeygen(param0: native.Array<number>): void;
					public cryptoAuthHMACSha512Final(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: native.Array<number>): boolean;
					public cryptoKxClientSessionKeys(param0: com.goterl.lazycode.lazysodium.utils.KeyPair, param1: com.goterl.lazycode.lazysodium.utils.KeyPair): com.goterl.lazycode.lazysodium.utils.SessionPair;
					public cryptoAeadAES256GCMKeygen(param0: native.Array<number>): void;
					public cryptoHashSha256Update(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256, param1: native.Array<number>, param2: number): boolean;
					public cryptoKdfDeriveFromKey(param0: native.Array<number>, param1: number, param2: number, param3: native.Array<number>, param4: native.Array<number>): number;
					public cryptoStreamChacha20IetfXorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
					public cryptoGenericHashFinal(param0: native.Array<number>, param1: number): string;
					public convertSecretKeyEd25519ToCurve25519(param0: native.Array<number>, param1: native.Array<number>): boolean;
					public sodiumMProtectReadWrite(param0: com.sun.jna.Pointer): boolean;
					public static longToInt(param0: number): java.lang.Integer;
					public cryptoSecretStreamInitPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>): boolean;
					public cryptoHashSha512(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
					public cryptoBoxOpenDetachedAfterNm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): boolean;
					public cryptoAeadAES256GCMDecryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoHashSha512Update(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512, param1: native.Array<number>, param2: number): boolean;
					public cryptoKxKeypair(param0: native.Array<number>): com.goterl.lazycode.lazysodium.utils.KeyPair;
					public cryptoPwHashStrNeedsRehash(param0: native.Array<number>, param1: number, param2: com.sun.jna.NativeLong): boolean;
					public convertKeyPairEd25519ToCurve25519(param0: com.goterl.lazycode.lazysodium.utils.KeyPair): com.goterl.lazycode.lazysodium.utils.KeyPair;
					public cryptoAeadAES256GCMDecrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public str(param0: native.Array<number>, param1: java.nio.charset.Charset): string;
					public cryptoAeadXChaCha20Poly1305IetfEncryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): boolean;
					public cryptoStreamXorIc(param0: string, param1: native.Array<number>, param2: number, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
					public cryptoAuthHMACSha(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.Type, param1: string, param2: com.goterl.lazycode.lazysodium.utils.Key): string;
					public cryptoBoxSeedKeypair(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
					public cryptoHashSha256(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
					public cryptoStreamSalsa20XorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
					public cryptoSign(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>): boolean;
					public cryptoAuthHMACShaFinal(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256): string;
					public cryptoSignKeypair(): com.goterl.lazycode.lazysodium.utils.KeyPair;
					public cryptoAeadXChaCha20Poly1305IetfKeygen(param0: native.Array<number>): void;
					public res(param0: number, param1: any): any;
					public cryptoAuthHMACSha512(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public cryptoSecretBoxOpenDetached(param0: com.goterl.lazycode.lazysodium.utils.DetachedEncrypt, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key): string;
					public cryptoSecretBoxEasy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoAuthHMACSha256Keygen(param0: native.Array<number>): void;
					public cryptoBoxDetachedAfterNm(param0: string, param1: native.Array<number>, param2: string): com.goterl.lazycode.lazysodium.utils.DetachedEncrypt;
					public cryptoSecretBoxDetached(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.DetachedEncrypt;
					public cryptoPwHashStr(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: number, param4: com.sun.jna.NativeLong): boolean;
					public cryptoAeadXChaCha20Poly1305IetfDecryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoKxSeedKeypair(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
					public cryptoHashSha512Final(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512, param1: native.Array<number>): boolean;
					public cryptoAuthHMACSha512Verify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public randomBytesBuf(param0: number): native.Array<number>;
					public getSodium(): com.goterl.lazycode.lazysodium.Sodium;
					public sodiumMemZero(param0: native.Array<number>, param1: number): boolean;
					public cryptoSecretStreamInitPush(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.interfaces.SecretStream.State;
					public cryptoAeadChaCha20Poly1305Keygen(param0: native.Array<number>): void;
					public bytes(param0: string): native.Array<number>;
					public cryptoSecretStreamKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoAuthHMACSha512256Verify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public cryptoBoxBeforeNm(param0: com.goterl.lazycode.lazysodium.utils.KeyPair): string;
					public cryptoSignSeedKeypair(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
					public cryptoPwHashStrRemoveNulls(param0: string, param1: number, param2: com.sun.jna.NativeLong): string;
					public cryptoSignEd25519SkToSeed(param0: native.Array<number>, param1: native.Array<number>): boolean;
					public cryptoPwHashStrVerify(param0: string, param1: string): boolean;
					public cryptoBoxOpenEasyAfterNm(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoAuthHMACShaFinal(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512): string;
					public cryptoAuthHMACShaInit(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: com.goterl.lazycode.lazysodium.utils.Key): boolean;
					public cryptoHashSha256Init(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256): boolean;
					public cryptoSignOpen(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>): boolean;
					public sodiumMProtectReadOnly(param0: com.sun.jna.Pointer): boolean;
					public cryptoSecretStreamInitPull(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.interfaces.SecretStream.State;
					public cryptoBoxOpenEasy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>, param5: native.Array<number>): boolean;
					public cryptoAuthKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
					public removeNulls(param0: native.Array<number>): native.Array<number>;
					public cryptoAuthHMACSha512256Final(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: native.Array<number>): boolean;
					public cryptoSignEd25519SkToPk(param0: native.Array<number>, param1: native.Array<number>): boolean;
					public cryptoSecretStreamKeygen(param0: native.Array<number>): void;
					public cryptoStreamChaCha20Ietf(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
					public cryptoSecretBoxKeygen(param0: native.Array<number>): void;
					public cryptoSignDetached(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
					public sodiumHex2Bin(param0: string): native.Array<number>;
					public decrypt(param0: string, param1: string, param2: native.Array<number>, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): string;
					public cryptoStreamDefaultXorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): native.Array<number>;
					public toHexStr(param0: native.Array<number>): string;
					public cryptoBoxDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: native.Array<number>): boolean;
					public cryptoStreamChaCha20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoBoxEasy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>, param5: native.Array<number>): boolean;
					public cryptoStreamChaCha20IetfKeygen(param0: native.Array<number>): void;
					public constructor(param0: java.nio.charset.Charset);
					public cryptoStreamXSalsa20Keygen(param0: native.Array<number>): void;
					public cryptoPwHashStr(param0: string, param1: number, param2: com.sun.jna.NativeLong): string;
					public cryptoKxKeypair(param0: native.Array<number>, param1: native.Array<number>): boolean;
					public cryptoSecretStreamPull(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: string, param2: native.Array<number>): string;
					public nonce(param0: number): native.Array<number>;
					public cryptoScalarMultBase(param0: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoBoxOpenEasyAfterNm(param0: string, param1: native.Array<number>, param2: string): string;
					public cryptoKxServerSessionKeys(param0: com.goterl.lazycode.lazysodium.utils.Key, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.SessionPair;
					public cryptoKdfKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoGenericHashUpdate(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
					public cryptoStreamChaCha20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
					public cryptoStreamXorIcDecrypt(param0: string, param1: native.Array<number>, param2: number, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
					public cryptoSignVerifyDetached(param0: string, param1: string, param2: com.goterl.lazycode.lazysodium.utils.Key): boolean;
					public cryptoAeadXChaCha20Poly1305IetfEncrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoStreamSalsa20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoHashSha512Init(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512): boolean;
					public cryptoGenericHashStateBytes(): number;
					public cryptoSignKeypair(param0: native.Array<number>, param1: native.Array<number>): boolean;
					public cryptoAuthHMACShaInit(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: com.goterl.lazycode.lazysodium.utils.Key): boolean;
					public cryptoSecretBoxKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoHashSha256(param0: string): string;
					public wrongLen(param0: native.Array<number>, param1: number): boolean;
					public cryptoGenericHashUpdate(param0: native.Array<number>, param1: string): boolean;
					public encryptDetached(param0: string, param1: string, param2: native.Array<number>, param3: native.Array<number>, param4: com.goterl.lazycode.lazysodium.utils.Key, param5: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): com.goterl.lazycode.lazysodium.utils.DetachedEncrypt;
					public cryptoKxClientSessionKeys(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoStreamSalsa20Keygen(param0: native.Array<number>): void;
					public sodiumMUnlock(param0: native.Array<number>, param1: number): boolean;
					public cryptoAuthHMACSha512Init(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: native.Array<number>, param2: number): boolean;
					public cryptoAuthHMACShaInit(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: com.goterl.lazycode.lazysodium.utils.Key): boolean;
					public cryptoSecretBoxOpenEasy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoAeadChaCha20Poly1305IetfKeygen(param0: native.Array<number>): void;
					public cryptoSecretBoxOpenEasy(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key): string;
					public randomBytesDeterministic(param0: number, param1: native.Array<number>): native.Array<number>;
					public cryptoHashSha256Final(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256): string;
					public cryptoSignSeedKeypair(param0: native.Array<number>): com.goterl.lazycode.lazysodium.utils.KeyPair;
					public cryptoStreamXSalsa20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
					public cryptoAuthHMACSha512256(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public cryptoGenericHash(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number): boolean;
					public decryptDetached(param0: com.goterl.lazycode.lazysodium.utils.DetachedEncrypt, param1: string, param2: native.Array<number>, param3: native.Array<number>, param4: com.goterl.lazycode.lazysodium.utils.Key, param5: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): com.goterl.lazycode.lazysodium.utils.DetachedDecrypt;
					public cryptoAuthVerify(param0: string, param1: string, param2: com.goterl.lazycode.lazysodium.utils.Key): boolean;
					public cryptoKxKeypair(): com.goterl.lazycode.lazysodium.utils.KeyPair;
					public cryptoKxServerSessionKeys(param0: com.goterl.lazycode.lazysodium.utils.KeyPair, param1: com.goterl.lazycode.lazysodium.utils.KeyPair): com.goterl.lazycode.lazysodium.utils.SessionPair;
					public cryptoGenericHashKeygen(param0: native.Array<number>): void;
					public randomBytesUniform(param0: number): number;
					public cryptoBoxKeypair(param0: native.Array<number>, param1: native.Array<number>): boolean;
					public static main(param0: native.Array<string>): void;
					public cryptoAuthHMACShaUpdate(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: string): boolean;
					public sodiumBin2Hex(param0: native.Array<number>): string;
					public cryptoSignVerifyDetached(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public cryptoKdfDeriveFromKey(param0: number, param1: number, param2: string, param3: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoBoxDetachedAfterNm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): boolean;
					public cryptoStreamKeygen(param0: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoBoxBeforeNm(param0: native.Array<number>, param1: native.Array<number>): string;
					public cryptoSecretBoxDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): boolean;
					public cryptoStreamXSalsa20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoSecretBoxOpenDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): boolean;
					public cryptoBoxBeforeNm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
					public cryptoGenericHashInit(param0: native.Array<number>, param1: number): boolean;
					public cryptoGenericHashFinal(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
					public static toHex(param0: native.Array<number>): string;
					public cryptoAuthHMACSha512256Update(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: native.Array<number>, param2: number): boolean;
					public cryptoAuthHMACShaFinal(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256): string;
					public cryptoAuthHMACShaKeygen(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.Type): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoStreamChaCha20Keygen(param0: native.Array<number>): void;
					public cryptoHashSha512(param0: string): string;
					public cryptoStreamChacha20XorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
					public cryptoScalarMultBase(param0: native.Array<number>, param1: native.Array<number>): boolean;
					public cryptoPwHashStrVerify(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
					public cryptoSignSecretKeyPair(param0: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.KeyPair;
					public cryptoAuthHMACShaUpdate(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: string): boolean;
					public cryptoSignOpen(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
					public toBinary(param0: string): native.Array<number>;
					public cryptoGenericHash(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
					public cryptoHashSha256Final(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256, param1: native.Array<number>): boolean;
					public cryptoAeadAES256GCMEncrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoBoxSeal(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public cryptoAuthVerify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public cryptoAeadChaCha20Poly1305IetfEncrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoBoxOpenDetachedAfterNm(param0: com.goterl.lazycode.lazysodium.utils.DetachedEncrypt, param1: native.Array<number>, param2: string): com.goterl.lazycode.lazysodium.utils.DetachedDecrypt;
					public cryptoSecretStreamPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: number): boolean;
					public convertPublicKeyEd25519ToCurve25519(param0: native.Array<number>, param1: native.Array<number>): boolean;
					public cryptoBoxEasyAfterNm(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoStreamSalsa20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
					public cryptoSecretStreamPull(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: number): boolean;
					public cryptoAuthHMACSha512256Keygen(param0: native.Array<number>): void;
					public cryptoSecretBoxEasy(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key): string;
					public sodiumFree(param0: com.sun.jna.Pointer): void;
					public cryptoAeadXChaCha20Poly1305IetfDecrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoBoxOpenEasy(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.KeyPair): string;
					public cryptoGenericHashKeygen(param0: number): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoHashSha512Final(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512): string;
					public cryptoAuthHMACSha256Final(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: native.Array<number>): boolean;
					public cryptoKxClientSessionKeys(param0: com.goterl.lazycode.lazysodium.utils.Key, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.SessionPair;
					public cryptoHashSha256Update(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256, param1: string): boolean;
					public cryptoGenericHashInit(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: number): boolean;
					public cryptoAuthHMACShaVerify(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.Type, param1: string, param2: string, param3: com.goterl.lazycode.lazysodium.utils.Key): boolean;
					public cryptoGenericHashKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoShortHashKeygen(param0: native.Array<number>): void;
					public sodiumMalloc(param0: number): com.sun.jna.Pointer;
					public cryptoPwHash(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: com.sun.jna.NativeLong, param7: com.goterl.lazycode.lazysodium.interfaces.PwHash.Alg): boolean;
					public cryptoAeadChaCha20Poly1305IetfEncryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): boolean;
					public cryptoAuthHMACSha512256Init(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: native.Array<number>, param2: number): boolean;
					public cryptoAeadChaCha20Poly1305EncryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): boolean;
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export class LazySodiumAndroid extends com.goterl.lazycode.lazysodium.LazySodium {
					public static class: java.lang.Class<com.goterl.lazycode.lazysodium.LazySodiumAndroid>;
					public successful(param0: number): boolean;
					public sodiumAllocArray(param0: number, param1: number): com.sun.jna.Pointer;
					public decrypt(param0: string, param1: string, param2: native.Array<number>, param3: native.Array<number>, param4: com.goterl.lazycode.lazysodium.utils.Key, param5: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): string;
					public cryptoSecretStreamRekey(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State): void;
					public cryptoGenericHash(param0: string): string;
					public cryptoGenericHash(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number): boolean;
					public cryptoSecretStreamPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: string, param2: number): string;
					public cryptoBoxSeedKeypair(param0: native.Array<number>): com.goterl.lazycode.lazysodium.utils.KeyPair;
					public cryptoShortHash(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public constructor();
					public cryptoAeadChaCha20Poly1305Encrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public encrypt(param0: string, param1: string, param2: native.Array<number>, param3: native.Array<number>, param4: com.goterl.lazycode.lazysodium.utils.Key, param5: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): string;
					public cryptoAuthKeygen(param0: native.Array<number>): void;
					public cryptoAeadChaCha20Poly1305Decrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoAuthHMACSha512Keygen(param0: native.Array<number>): void;
					public wrongLen(param0: number, param1: number): boolean;
					public cryptoPwHash(param0: string, param1: number, param2: native.Array<number>, param3: number, param4: com.sun.jna.NativeLong, param5: com.goterl.lazycode.lazysodium.interfaces.PwHash.Alg): string;
					public cryptoSecretStreamPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: number): boolean;
					public encrypt(param0: string, param1: string, param2: native.Array<number>, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): string;
					public cryptoKxServerSessionKeys(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoShortHash(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
					public constructor(param0: com.goterl.lazycode.lazysodium.SodiumAndroid);
					public cryptoShortHashKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoAuth(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public sodiumMLock(param0: native.Array<number>, param1: number): boolean;
					public cryptoSecretStreamPull(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number): boolean;
					public cryptoStreamXor(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key, param3: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
					public cryptoSecretStreamPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: number): boolean;
					public cryptoBoxSealOpen(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public randomBytesRandom(): number;
					public cryptoSign(param0: string, param1: string): string;
					public cryptoAeadChaCha20Poly1305DecryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoAeadChaCha20Poly1305IetfDecrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoBoxEasyAfterNm(param0: string, param1: native.Array<number>, param2: string): string;
					public cryptoGenericHashInit(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: number): boolean;
					public cryptoScalarMult(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
					public keygen(param0: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoStreamChaCha20IetfXor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoSecretStreamInitPull(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>): boolean;
					public sodiumMProtectNoAccess(param0: com.sun.jna.Pointer): boolean;
					public cryptoBoxEasy(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.KeyPair): string;
					public cryptoBoxOpenDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>, param5: native.Array<number>, param6: native.Array<number>): boolean;
					public cryptoAuthHMACShaUpdate(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: string): boolean;
					public sodiumPad(param0: number, param1: native.Array<string>, param2: number, param3: number, param4: number): boolean;
					public cryptoHashSha512Update(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512, param1: string): boolean;
					public cryptoAuthHMACSha256Init(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: native.Array<number>, param2: number): boolean;
					public sodiumInit(): number;
					public cryptoAeadAES256GCMEncryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): boolean;
					public cryptoStream(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): native.Array<number>;
					public cryptoAuthHMACSha512Update(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: native.Array<number>, param2: number): boolean;
					public cryptoAuthHMACSha256(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public cryptoAeadChaCha20Poly1305IetfDecryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoScalarMult(param0: com.goterl.lazycode.lazysodium.utils.Key, param1: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoSignDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>): boolean;
					public cryptoAeadAES256GCMIsAvailable(): boolean;
					public sodiumUnpad(param0: number, param1: native.Array<string>, param2: number, param3: number): boolean;
					public str(param0: native.Array<number>): string;
					public cryptoAuthHMACSha256Update(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: native.Array<number>, param2: number): boolean;
					public cryptoBoxKeypair(): com.goterl.lazycode.lazysodium.utils.KeyPair;
					public cryptoAuthHMACSha256Verify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public cryptoStreamXorDecrypt(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key, param3: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
					public cryptoAuth(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
					public cryptoKdfKeygen(param0: native.Array<number>): void;
					public cryptoAuthHMACSha512Final(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: native.Array<number>): boolean;
					public cryptoKxClientSessionKeys(param0: com.goterl.lazycode.lazysodium.utils.KeyPair, param1: com.goterl.lazycode.lazysodium.utils.KeyPair): com.goterl.lazycode.lazysodium.utils.SessionPair;
					public cryptoAeadAES256GCMKeygen(param0: native.Array<number>): void;
					public cryptoHashSha256Update(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256, param1: native.Array<number>, param2: number): boolean;
					public cryptoKdfDeriveFromKey(param0: native.Array<number>, param1: number, param2: number, param3: native.Array<number>, param4: native.Array<number>): number;
					public cryptoGenericHashFinal(param0: native.Array<number>, param1: number): string;
					public cryptoStreamChacha20IetfXorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
					public convertSecretKeyEd25519ToCurve25519(param0: native.Array<number>, param1: native.Array<number>): boolean;
					public sodiumMProtectReadWrite(param0: com.sun.jna.Pointer): boolean;
					public cryptoSecretStreamInitPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>): boolean;
					public cryptoHashSha512(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
					public cryptoBoxOpenDetachedAfterNm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): boolean;
					public cryptoAeadAES256GCMDecryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoHashSha512Update(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512, param1: native.Array<number>, param2: number): boolean;
					public cryptoPwHashStrNeedsRehash(param0: native.Array<number>, param1: number, param2: com.sun.jna.NativeLong): boolean;
					public cryptoKxKeypair(param0: native.Array<number>): com.goterl.lazycode.lazysodium.utils.KeyPair;
					public convertKeyPairEd25519ToCurve25519(param0: com.goterl.lazycode.lazysodium.utils.KeyPair): com.goterl.lazycode.lazysodium.utils.KeyPair;
					public cryptoAeadAES256GCMDecrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public str(param0: native.Array<number>, param1: java.nio.charset.Charset): string;
					public cryptoAeadXChaCha20Poly1305IetfEncryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): boolean;
					public cryptoAuthHMACSha(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.Type, param1: string, param2: com.goterl.lazycode.lazysodium.utils.Key): string;
					public cryptoStreamXorIc(param0: string, param1: native.Array<number>, param2: number, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
					public getSodium(): com.goterl.lazycode.lazysodium.SodiumAndroid;
					public cryptoBoxSeedKeypair(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
					public cryptoHashSha256(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
					public cryptoStreamSalsa20XorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
					public cryptoSign(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>): boolean;
					public cryptoAuthHMACShaFinal(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256): string;
					public cryptoSignKeypair(): com.goterl.lazycode.lazysodium.utils.KeyPair;
					public cryptoAeadXChaCha20Poly1305IetfKeygen(param0: native.Array<number>): void;
					public res(param0: number, param1: any): any;
					public cryptoAuthHMACSha512(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public cryptoSecretBoxOpenDetached(param0: com.goterl.lazycode.lazysodium.utils.DetachedEncrypt, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key): string;
					public cryptoSecretBoxEasy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoAuthHMACSha256Keygen(param0: native.Array<number>): void;
					public cryptoBoxDetachedAfterNm(param0: string, param1: native.Array<number>, param2: string): com.goterl.lazycode.lazysodium.utils.DetachedEncrypt;
					public cryptoSecretBoxDetached(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.DetachedEncrypt;
					public cryptoPwHashStr(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: number, param4: com.sun.jna.NativeLong): boolean;
					public cryptoAeadXChaCha20Poly1305IetfDecryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoKxSeedKeypair(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
					public cryptoHashSha512Final(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512, param1: native.Array<number>): boolean;
					public cryptoAuthHMACSha512Verify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public getSodium(): com.goterl.lazycode.lazysodium.Sodium;
					public randomBytesBuf(param0: number): native.Array<number>;
					public sodiumMemZero(param0: native.Array<number>, param1: number): boolean;
					public cryptoSecretStreamInitPush(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.interfaces.SecretStream.State;
					public cryptoAeadChaCha20Poly1305Keygen(param0: native.Array<number>): void;
					public bytes(param0: string): native.Array<number>;
					public cryptoSecretStreamKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoAuthHMACSha512256Verify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public cryptoBoxBeforeNm(param0: com.goterl.lazycode.lazysodium.utils.KeyPair): string;
					public cryptoSignSeedKeypair(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
					public cryptoPwHashStrRemoveNulls(param0: string, param1: number, param2: com.sun.jna.NativeLong): string;
					public cryptoSignEd25519SkToSeed(param0: native.Array<number>, param1: native.Array<number>): boolean;
					public cryptoPwHashStrVerify(param0: string, param1: string): boolean;
					public cryptoBoxOpenEasyAfterNm(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoAuthHMACShaFinal(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512): string;
					public cryptoAuthHMACShaInit(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: com.goterl.lazycode.lazysodium.utils.Key): boolean;
					public cryptoHashSha256Init(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256): boolean;
					public cryptoSignOpen(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>): boolean;
					public sodiumMProtectReadOnly(param0: com.sun.jna.Pointer): boolean;
					public cryptoSecretStreamInitPull(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.interfaces.SecretStream.State;
					public cryptoAuthKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoBoxOpenEasy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>, param5: native.Array<number>): boolean;
					public removeNulls(param0: native.Array<number>): native.Array<number>;
					public cryptoAuthHMACSha512256Final(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: native.Array<number>): boolean;
					public cryptoSignEd25519SkToPk(param0: native.Array<number>, param1: native.Array<number>): boolean;
					public cryptoSecretStreamKeygen(param0: native.Array<number>): void;
					public cryptoStreamChaCha20Ietf(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
					public cryptoSecretBoxKeygen(param0: native.Array<number>): void;
					public cryptoSignDetached(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
					public sodiumHex2Bin(param0: string): native.Array<number>;
					public decrypt(param0: string, param1: string, param2: native.Array<number>, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): string;
					public cryptoBoxDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: native.Array<number>): boolean;
					public cryptoStreamChaCha20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoBoxEasy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>, param5: native.Array<number>): boolean;
					public cryptoStreamChaCha20IetfKeygen(param0: native.Array<number>): void;
					public constructor(param0: java.nio.charset.Charset);
					public cryptoStreamXSalsa20Keygen(param0: native.Array<number>): void;
					public cryptoPwHashStr(param0: string, param1: number, param2: com.sun.jna.NativeLong): string;
					public cryptoKxKeypair(param0: native.Array<number>, param1: native.Array<number>): boolean;
					public cryptoSecretStreamPull(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: string, param2: native.Array<number>): string;
					public nonce(param0: number): native.Array<number>;
					public cryptoScalarMultBase(param0: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoBoxOpenEasyAfterNm(param0: string, param1: native.Array<number>, param2: string): string;
					public cryptoKxServerSessionKeys(param0: com.goterl.lazycode.lazysodium.utils.Key, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.SessionPair;
					public cryptoGenericHashUpdate(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
					public cryptoKdfKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoStreamXorIcDecrypt(param0: string, param1: native.Array<number>, param2: number, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
					public cryptoStreamChaCha20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
					public cryptoSignVerifyDetached(param0: string, param1: string, param2: com.goterl.lazycode.lazysodium.utils.Key): boolean;
					public cryptoAeadXChaCha20Poly1305IetfEncrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoStreamSalsa20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoGenericHashStateBytes(): number;
					public cryptoHashSha512Init(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512): boolean;
					public cryptoSignKeypair(param0: native.Array<number>, param1: native.Array<number>): boolean;
					public cryptoAuthHMACShaInit(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: com.goterl.lazycode.lazysodium.utils.Key): boolean;
					public cryptoSecretBoxKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoHashSha256(param0: string): string;
					public wrongLen(param0: native.Array<number>, param1: number): boolean;
					public cryptoGenericHashUpdate(param0: native.Array<number>, param1: string): boolean;
					public encryptDetached(param0: string, param1: string, param2: native.Array<number>, param3: native.Array<number>, param4: com.goterl.lazycode.lazysodium.utils.Key, param5: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): com.goterl.lazycode.lazysodium.utils.DetachedEncrypt;
					public cryptoKxClientSessionKeys(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoStreamSalsa20Keygen(param0: native.Array<number>): void;
					public sodiumMUnlock(param0: native.Array<number>, param1: number): boolean;
					public cryptoAuthHMACSha512Init(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: native.Array<number>, param2: number): boolean;
					public cryptoAuthHMACShaInit(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: com.goterl.lazycode.lazysodium.utils.Key): boolean;
					public cryptoSecretBoxOpenEasy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoAeadChaCha20Poly1305IetfKeygen(param0: native.Array<number>): void;
					public cryptoSecretBoxOpenEasy(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key): string;
					public randomBytesDeterministic(param0: number, param1: native.Array<number>): native.Array<number>;
					public cryptoHashSha256Final(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256): string;
					public cryptoSignSeedKeypair(param0: native.Array<number>): com.goterl.lazycode.lazysodium.utils.KeyPair;
					public cryptoStreamXSalsa20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
					public cryptoGenericHash(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number): boolean;
					public cryptoAuthHMACSha512256(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public decryptDetached(param0: com.goterl.lazycode.lazysodium.utils.DetachedEncrypt, param1: string, param2: native.Array<number>, param3: native.Array<number>, param4: com.goterl.lazycode.lazysodium.utils.Key, param5: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): com.goterl.lazycode.lazysodium.utils.DetachedDecrypt;
					public cryptoAuthVerify(param0: string, param1: string, param2: com.goterl.lazycode.lazysodium.utils.Key): boolean;
					public cryptoKxKeypair(): com.goterl.lazycode.lazysodium.utils.KeyPair;
					public cryptoKxServerSessionKeys(param0: com.goterl.lazycode.lazysodium.utils.KeyPair, param1: com.goterl.lazycode.lazysodium.utils.KeyPair): com.goterl.lazycode.lazysodium.utils.SessionPair;
					public cryptoGenericHashKeygen(param0: native.Array<number>): void;
					public cryptoBoxKeypair(param0: native.Array<number>, param1: native.Array<number>): boolean;
					public randomBytesUniform(param0: number): number;
					public cryptoAuthHMACShaUpdate(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: string): boolean;
					public sodiumBin2Hex(param0: native.Array<number>): string;
					public cryptoSignVerifyDetached(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public cryptoKdfDeriveFromKey(param0: number, param1: number, param2: string, param3: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoBoxDetachedAfterNm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): boolean;
					public cryptoStreamKeygen(param0: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoBoxBeforeNm(param0: native.Array<number>, param1: native.Array<number>): string;
					public cryptoSecretBoxDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): boolean;
					public cryptoStreamXSalsa20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoSecretBoxOpenDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): boolean;
					public cryptoBoxBeforeNm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
					public cryptoGenericHashInit(param0: native.Array<number>, param1: number): boolean;
					public cryptoGenericHashFinal(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
					public constructor(param0: com.goterl.lazycode.lazysodium.SodiumAndroid, param1: java.nio.charset.Charset);
					public cryptoAuthHMACSha512256Update(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: native.Array<number>, param2: number): boolean;
					public cryptoAuthHMACShaFinal(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256): string;
					public cryptoAuthHMACShaKeygen(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.Type): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoStreamChaCha20Keygen(param0: native.Array<number>): void;
					public cryptoHashSha512(param0: string): string;
					public cryptoStreamChacha20XorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
					public cryptoScalarMultBase(param0: native.Array<number>, param1: native.Array<number>): boolean;
					public cryptoPwHashStrVerify(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
					public cryptoAuthHMACShaUpdate(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: string): boolean;
					public cryptoSignSecretKeyPair(param0: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.KeyPair;
					public cryptoSignOpen(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
					public cryptoGenericHash(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
					public cryptoHashSha256Final(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256, param1: native.Array<number>): boolean;
					public cryptoAeadAES256GCMEncrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoBoxSeal(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public cryptoAuthVerify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
					public cryptoAeadChaCha20Poly1305IetfEncrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoBoxOpenDetachedAfterNm(param0: com.goterl.lazycode.lazysodium.utils.DetachedEncrypt, param1: native.Array<number>, param2: string): com.goterl.lazycode.lazysodium.utils.DetachedDecrypt;
					public cryptoSecretStreamPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: number): boolean;
					public convertPublicKeyEd25519ToCurve25519(param0: native.Array<number>, param1: native.Array<number>): boolean;
					public cryptoBoxEasyAfterNm(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
					public cryptoStreamSalsa20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
					public cryptoSecretStreamPull(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: number): boolean;
					public cryptoAuthHMACSha512256Keygen(param0: native.Array<number>): void;
					public cryptoSecretBoxEasy(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key): string;
					public sodiumFree(param0: com.sun.jna.Pointer): void;
					public cryptoAeadXChaCha20Poly1305IetfDecrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
					public cryptoGenericHashKeygen(param0: number): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoBoxOpenEasy(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.KeyPair): string;
					public cryptoHashSha512Final(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512): string;
					public cryptoAuthHMACSha256Final(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: native.Array<number>): boolean;
					public cryptoKxClientSessionKeys(param0: com.goterl.lazycode.lazysodium.utils.Key, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.SessionPair;
					public cryptoHashSha256Update(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256, param1: string): boolean;
					public cryptoGenericHashInit(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: number): boolean;
					public cryptoAuthHMACShaVerify(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.Type, param1: string, param2: string, param3: com.goterl.lazycode.lazysodium.utils.Key): boolean;
					public cryptoGenericHashKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
					public cryptoShortHashKeygen(param0: native.Array<number>): void;
					public cryptoPwHash(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: com.sun.jna.NativeLong, param7: com.goterl.lazycode.lazysodium.interfaces.PwHash.Alg): boolean;
					public sodiumMalloc(param0: number): com.sun.jna.Pointer;
					public cryptoAeadChaCha20Poly1305IetfEncryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): boolean;
					public cryptoAuthHMACSha512256Init(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: native.Array<number>, param2: number): boolean;
					public cryptoAeadChaCha20Poly1305EncryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): boolean;
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export class Sodium {
					public static class: java.lang.Class<com.goterl.lazycode.lazysodium.Sodium>;
					public sodium_mlock(param0: native.Array<number>, param1: number): number;
					public crypto_stream_chacha20_xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): number;
					public crypto_generichash_keygen(param0: native.Array<number>): void;
					public crypto_aead_aes256gcm_decrypt_afternm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: com.goterl.lazycode.lazysodium.interfaces.AEAD.StateAES): number;
					public crypto_aead_chacha20poly1305_decrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): number;
					public crypto_secretbox_open_easy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): number;
					public crypto_secretstream_xchacha20poly1305_keygen(param0: native.Array<number>): void;
					public crypto_auth_hmacsha256_update(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: native.Array<number>, param2: number): number;
					public crypto_aead_aes256gcm_encrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): number;
					public crypto_pwhash(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: com.sun.jna.NativeLong, param7: number): number;
					public crypto_aead_xchacha20poly1305_ietf_encrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): number;
					public crypto_aead_xchacha20poly1305_ietf_decrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): number;
					public crypto_kx_keypair(param0: native.Array<number>, param1: native.Array<number>): number;
					public sodium_mprotect_readonly(param0: com.sun.jna.Pointer): number;
					public constructor();
					public crypto_aead_chacha20poly1305_encrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): number;
					public crypto_kx_client_session_keys(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>): number;
					public crypto_sign_ed25519_sk_to_seed(param0: native.Array<number>, param1: native.Array<number>): number;
					public crypto_generichash_final(param0: native.Array<number>, param1: native.Array<number>, param2: number): number;
					public crypto_kdf_keygen(param0: native.Array<number>): void;
					public sodium_base64_encoded_len(param0: number, param1: number): number;
					public crypto_auth_hmacsha512256_keygen(param0: native.Array<number>): void;
					public crypto_box_beforenm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): number;
					public sodium_munlock(param0: native.Array<number>, param1: number): number;
					public crypto_sign_ed25519_sk_to_curve25519(param0: native.Array<number>, param1: native.Array<number>): number;
					public crypto_pwhash_str_verify(param0: native.Array<number>, param1: native.Array<number>, param2: number): number;
					public crypto_aead_chacha20poly1305_encrypt_detached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): number;
					public crypto_hash_sha256_update(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256, param1: native.Array<number>, param2: number): number;
					public crypto_generichash(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number): number;
					public crypto_sign_keypair(param0: native.Array<number>, param1: native.Array<number>): number;
					public crypto_auth_hmacsha512256_verify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): number;
					public sodium_init(): number;
					public crypto_secretstream_xchacha20poly1305_messagebytes_max(): number;
					public crypto_aead_aes256gcm_decrypt_detached_afternm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: com.goterl.lazycode.lazysodium.interfaces.AEAD.StateAES): number;
					public crypto_stream_salsa20_xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): number;
					public crypto_secretstream_xchacha20poly1305_tag_message(): number;
					public crypto_hash_sha256_init(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256): number;
					public crypto_box_easy_afternm(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): number;
					public crypto_hash_sha512_init(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512): number;
					public crypto_aead_chacha20poly1305_decrypt_detached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): number;
					public crypto_secretstream_xchacha20poly1305_push(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: number): number;
					public sodium_bin2base64(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number, param4: number): string;
					public crypto_stream_chacha20_ietf_xor_ic(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): number;
					public randombytes_uniform(param0: number): number;
					public crypto_secretstream_xchacha20poly1305_tag_push(): number;
					public crypto_auth_hmacsha512256_final(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: native.Array<number>): number;
					public crypto_stream_chacha20_ietf_keygen(param0: native.Array<number>): void;
					public crypto_auth_hmacsha512256(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): number;
					public crypto_sign_seed_keypair(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): number;
					public crypto_auth_verify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): number;
					public crypto_auth_hmacsha512_init(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: native.Array<number>, param2: number): number;
					public randombytes_buf_deterministic(param0: native.Array<number>, param1: number, param2: native.Array<number>): void;
					public crypto_stream_chacha20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): number;
					public crypto_shorthash(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): number;
					public crypto_auth_hmacsha512256_init(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: native.Array<number>, param2: number): number;
					public crypto_auth_hmacsha256_init(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: native.Array<number>, param2: number): number;
					public crypto_sign_ed25519_sk_to_pk(param0: native.Array<number>, param1: native.Array<number>): number;
					public crypto_auth_hmacsha512256_update(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: native.Array<number>, param2: number): number;
					public crypto_stream_salsa20_keygen(param0: native.Array<number>): void;
					public crypto_secretstream_xchacha20poly1305_init_push(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>): number;
					public crypto_secretstream_xchacha20poly1305_tag_final(): number;
					public randombytes_buf(param0: native.Array<number>, param1: number): void;
					public crypto_box_easy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>, param5: native.Array<number>): number;
					public crypto_box_detached_afternm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): number;
					public crypto_box_seal_open(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): number;
					public crypto_hash_sha256_final(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256, param1: native.Array<number>): number;
					public crypto_stream_xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): number;
					public crypto_generichash_init(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: number): number;
					public sodium_increment(param0: native.Array<number>, param1: number): void;
					public crypto_secretbox_keygen(param0: native.Array<number>): void;
					public crypto_auth_hmacsha256(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): number;
					public crypto_hash_sha256(param0: native.Array<number>, param1: native.Array<number>, param2: number): number;
					public crypto_secretstream_xchacha20poly1305_pull(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: number): number;
					public crypto_generichash_update(param0: native.Array<number>, param1: native.Array<number>, param2: number): number;
					public crypto_core_hchacha20(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>): number;
					public crypto_box_open_easy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>, param5: native.Array<number>): number;
					public crypto_hash_sha512_update(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512, param1: native.Array<number>, param2: number): number;
					public crypto_auth_hmacsha256_keygen(param0: native.Array<number>): void;
					public crypto_box_open_easy_afternm(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): number;
					public crypto_pwhash_str(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: number, param4: com.sun.jna.NativeLong): number;
					public crypto_secretstream_xchacha20poly1305_headerbytes(): number;
					public crypto_stream(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): number;
					public sodium_hex2bin(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: number): number;
					public sodium_memzero(param0: native.Array<number>, param1: number): number;
					public crypto_stream_salsa20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): number;
					public crypto_stream_salsa20_xor_ic(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): number;
					public crypto_stream_keygen(param0: native.Array<number>): void;
					public sodium_compare(param0: native.Array<number>, param1: native.Array<number>, param2: number): number;
					public crypto_secretbox_open_detached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): number;
					public crypto_aead_aes256gcm_is_available(): number;
					public crypto_scalarmult_base(param0: native.Array<number>, param1: native.Array<number>): number;
					public crypto_auth_hmacsha512_verify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): number;
					public crypto_kdf_derive_from_key(param0: native.Array<number>, param1: number, param2: number, param3: native.Array<number>, param4: native.Array<number>): number;
					public crypto_generichash_blake2b_salt_personal(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: number, param7: native.Array<number>): number;
					public crypto_box_seal(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): number;
					public crypto_aead_aes256gcm_keygen(param0: native.Array<number>): void;
					public crypto_shorthash_keygen(param0: native.Array<number>): number;
					public crypto_box_seed_keypair(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): number;
					public sodium_base642bin(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: number, param7: number): number;
					public crypto_secretbox_detached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): number;
					public sodium_pad(param0: number, param1: native.Array<string>, param2: number, param3: number, param4: number): number;
					public randombytes_random(): number;
					public crypto_box_keypair(param0: native.Array<number>, param1: native.Array<number>): number;
					public crypto_aead_chacha20poly1305_ietf_encrypt_detached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): number;
					public crypto_hash_sha512_final(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512, param1: native.Array<number>): number;
					public crypto_auth_hmacsha256_verify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): number;
					public sodium_stackzero(param0: number): void;
					public crypto_box_open_detached_afternm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): number;
					public crypto_auth(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): number;
					public crypto_auth_hmacsha512_update(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: native.Array<number>, param2: number): number;
					public crypto_aead_chacha20poly1305_ietf_keygen(param0: native.Array<number>): void;
					public sodium_is_zero(param0: native.Array<number>, param1: number): number;
					public crypto_sign_verify_detached(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): number;
					public crypto_secretstream_xchacha20poly1305_tag_rekey(): number;
					public crypto_aead_chacha20poly1305_ietf_decrypt_detached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): number;
					public crypto_aead_aes256gcm_encrypt_detached_afternm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: com.goterl.lazycode.lazysodium.interfaces.AEAD.StateAES): number;
					public sodium_unpad(param0: number, param1: native.Array<string>, param2: number, param3: number): number;
					public crypto_generichash_statebytes(): number;
					public crypto_sign(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>): number;
					public crypto_aead_chacha20poly1305_ietf_decrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): number;
					public sodium_malloc(param0: number): com.sun.jna.Pointer;
					public crypto_kx_seed_keypair(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): number;
					public crypto_sign_open(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>): number;
					public crypto_auth_hmacsha512_keygen(param0: native.Array<number>): void;
					public crypto_kx_server_session_keys(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>): number;
					public crypto_aead_aes256gcm_beforenm(param0: com.goterl.lazycode.lazysodium.interfaces.AEAD.StateAES, param1: native.Array<number>): number;
					public crypto_sign_detached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>): number;
					public crypto_hash_sha512(param0: native.Array<number>, param1: native.Array<number>, param2: number): number;
					public onRegistered(): void;
					public crypto_scalarmult(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): number;
					public crypto_auth_hmacsha512_final(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: native.Array<number>): number;
					public sodium_mprotect_noaccess(param0: com.sun.jna.Pointer): number;
					public crypto_aead_xchacha20poly1305_ietf_keygen(param0: native.Array<number>): void;
					public crypto_box_detached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: native.Array<number>): number;
					public crypto_aead_xchacha20poly1305_ietf_encrypt_detached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): number;
					public sodium_add(param0: native.Array<number>, param1: native.Array<number>, param2: number): void;
					public crypto_box_open_detached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>, param5: native.Array<number>, param6: native.Array<number>): number;
					public sodium_mprotect_readwrite(param0: com.sun.jna.Pointer): number;
					public sodium_bin2hex(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number): string;
					public crypto_aead_chacha20poly1305_keygen(param0: native.Array<number>): void;
					public crypto_aead_xchacha20poly1305_ietf_decrypt_detached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): number;
					public crypto_secretstream_xchacha20poly1305_abytes(): number;
					public crypto_pwhash_str_needs_rehash(param0: native.Array<number>, param1: number, param2: com.sun.jna.NativeLong): number;
					public sodium_free(param0: com.sun.jna.Pointer): void;
					public crypto_auth_hmacsha512(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): number;
					public crypto_aead_aes256gcm_decrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): number;
					public crypto_auth_hmacsha256_final(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: native.Array<number>): number;
					public crypto_secretbox_easy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): number;
					public crypto_aead_aes256gcm_decrypt_detached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): number;
					public crypto_sign_ed25519_pk_to_curve25519(param0: native.Array<number>, param1: native.Array<number>): number;
					public crypto_stream_chacha20_ietf(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): number;
					public crypto_aead_aes256gcm_encrypt_detached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): number;
					public crypto_stream_chacha20_xor_ic(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): number;
					public crypto_auth_keygen(param0: native.Array<number>): void;
					public crypto_secretstream_xchacha20poly1305_keybytes(): number;
					public crypto_secretstream_xchacha20poly1305_init_pull(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>): number;
					public sodium_memcmp(param0: native.Array<number>, param1: native.Array<number>, param2: number): number;
					public crypto_stream_chacha20_ietf_xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): number;
					public sodium_allocarray(param0: number, param1: number): com.sun.jna.Pointer;
					public crypto_stream_chacha20_keygen(param0: native.Array<number>): void;
					public crypto_secretstream_xchacha20poly1305_rekey(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State): void;
					public crypto_aead_chacha20poly1305_ietf_encrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): number;
					public crypto_aead_aes256gcm_encrypt_afternm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: com.goterl.lazycode.lazysodium.interfaces.AEAD.StateAES): number;
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export class SodiumAndroid extends com.goterl.lazycode.lazysodium.Sodium {
					public static class: java.lang.Class<com.goterl.lazycode.lazysodium.SodiumAndroid>;
					public constructor(param0: string);
					public constructor();
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module exceptions {
					export class SodiumException {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.exceptions.SodiumException>;
						public constructor(param0: java.lang.Throwable);
						public constructor(param0: string, param1: java.lang.Throwable);
						public constructor(param0: string);
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class AEAD {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.AEAD>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.AEAD interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
						});
						public constructor();
						public static CHACHA20POLY1305_ABYTES: number;
						public static AES256GCM_KEYBYTES: number;
						public static CHACHA20POLY1305_IETF_ABYTES: number;
						public static CHACHA20POLY1305_IETF_KEYBYTES: number;
						public static XCHACHA20POLY1305_IETF_KEYBYTES: number;
						public static AES256GCM_NPUBBYTES: number;
						public static CHACHA20POLY1305_IETF_NPUBBYTES: number;
						public static AES256GCM_ABYTES: number;
						public static CHACHA20POLY1305_KEYBYTES: number;
						public static XCHACHA20POLY1305_IETF_ABYTES: number;
						public static AES256GCM_NSECBYTES: number;
						public static CHACHA20POLY1305_NPUBBYTES: number;
						public static XCHACHA20POLY1305_IETF_NPUBBYTES: number;
					}
					export module AEAD {
						export class Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.AEAD.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.AEAD$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								keygen(param0: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): com.goterl.lazycode.lazysodium.utils.Key;
								encrypt(param0: string, param1: string, param2: native.Array<number>, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): string;
								encrypt(param0: string, param1: string, param2: native.Array<number>, param3: native.Array<number>, param4: com.goterl.lazycode.lazysodium.utils.Key, param5: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): string;
								decrypt(param0: string, param1: string, param2: native.Array<number>, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): string;
								decrypt(param0: string, param1: string, param2: native.Array<number>, param3: native.Array<number>, param4: com.goterl.lazycode.lazysodium.utils.Key, param5: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): string;
								encryptDetached(param0: string, param1: string, param2: native.Array<number>, param3: native.Array<number>, param4: com.goterl.lazycode.lazysodium.utils.Key, param5: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): com.goterl.lazycode.lazysodium.utils.DetachedEncrypt;
								decryptDetached(param0: com.goterl.lazycode.lazysodium.utils.DetachedEncrypt, param1: string, param2: native.Array<number>, param3: native.Array<number>, param4: com.goterl.lazycode.lazysodium.utils.Key, param5: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): com.goterl.lazycode.lazysodium.utils.DetachedDecrypt;
							});
							public constructor();
							public decryptDetached(param0: com.goterl.lazycode.lazysodium.utils.DetachedEncrypt, param1: string, param2: native.Array<number>, param3: native.Array<number>, param4: com.goterl.lazycode.lazysodium.utils.Key, param5: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): com.goterl.lazycode.lazysodium.utils.DetachedDecrypt;
							public encryptDetached(param0: string, param1: string, param2: native.Array<number>, param3: native.Array<number>, param4: com.goterl.lazycode.lazysodium.utils.Key, param5: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): com.goterl.lazycode.lazysodium.utils.DetachedEncrypt;
							public encrypt(param0: string, param1: string, param2: native.Array<number>, param3: native.Array<number>, param4: com.goterl.lazycode.lazysodium.utils.Key, param5: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): string;
							public encrypt(param0: string, param1: string, param2: native.Array<number>, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): string;
							public keygen(param0: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): com.goterl.lazycode.lazysodium.utils.Key;
							public decrypt(param0: string, param1: string, param2: native.Array<number>, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): string;
							public decrypt(param0: string, param1: string, param2: native.Array<number>, param3: native.Array<number>, param4: com.goterl.lazycode.lazysodium.utils.Key, param5: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method): string;
						}
						export class Method {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.AEAD.Method>;
							public static CHACHA20_POLY1305: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method;
							public static CHACHA20_POLY1305_IETF: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method;
							public static XCHACHA20_POLY1305_IETF: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method;
							public static AES256GCM: com.goterl.lazycode.lazysodium.interfaces.AEAD.Method;
							public static valueOf(param0: string): com.goterl.lazycode.lazysodium.interfaces.AEAD.Method;
							public static values(): native.Array<com.goterl.lazycode.lazysodium.interfaces.AEAD.Method>;
						}
						export class Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.AEAD.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.AEAD$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoAeadChaCha20Poly1305Keygen(param0: native.Array<number>): void;
								cryptoAeadChaCha20Poly1305Encrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): boolean;
								cryptoAeadChaCha20Poly1305Decrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
								cryptoAeadChaCha20Poly1305EncryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): boolean;
								cryptoAeadChaCha20Poly1305DecryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
								cryptoAeadChaCha20Poly1305IetfKeygen(param0: native.Array<number>): void;
								cryptoAeadChaCha20Poly1305IetfEncrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): boolean;
								cryptoAeadChaCha20Poly1305IetfDecrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
								cryptoAeadChaCha20Poly1305IetfEncryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): boolean;
								cryptoAeadChaCha20Poly1305IetfDecryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
								cryptoAeadXChaCha20Poly1305IetfKeygen(param0: native.Array<number>): void;
								cryptoAeadXChaCha20Poly1305IetfEncrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): boolean;
								cryptoAeadXChaCha20Poly1305IetfDecrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
								cryptoAeadXChaCha20Poly1305IetfEncryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): boolean;
								cryptoAeadXChaCha20Poly1305IetfDecryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
								cryptoAeadAES256GCMKeygen(param0: native.Array<number>): void;
								cryptoAeadAES256GCMEncrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): boolean;
								cryptoAeadAES256GCMDecrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
								cryptoAeadAES256GCMEncryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): boolean;
								cryptoAeadAES256GCMDecryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
								cryptoAeadAES256GCMIsAvailable(): boolean;
							});
							public constructor();
							public cryptoAeadChaCha20Poly1305Decrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
							public cryptoAeadAES256GCMDecrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
							public cryptoAeadAES256GCMIsAvailable(): boolean;
							public cryptoAeadChaCha20Poly1305IetfKeygen(param0: native.Array<number>): void;
							public cryptoAeadXChaCha20Poly1305IetfEncrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): boolean;
							public cryptoAeadChaCha20Poly1305IetfDecrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
							public cryptoAeadXChaCha20Poly1305IetfDecrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
							public cryptoAeadAES256GCMKeygen(param0: native.Array<number>): void;
							public cryptoAeadChaCha20Poly1305DecryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
							public cryptoAeadChaCha20Poly1305IetfEncryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): boolean;
							public cryptoAeadChaCha20Poly1305Keygen(param0: native.Array<number>): void;
							public cryptoAeadChaCha20Poly1305IetfDecryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
							public cryptoAeadAES256GCMEncryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): boolean;
							public cryptoAeadAES256GCMDecryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
							public cryptoAeadXChaCha20Poly1305IetfDecryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>): boolean;
							public cryptoAeadChaCha20Poly1305IetfEncrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): boolean;
							public cryptoAeadChaCha20Poly1305EncryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): boolean;
							public cryptoAeadAES256GCMEncrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): boolean;
							public cryptoAeadChaCha20Poly1305Encrypt(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: native.Array<number>, param8: native.Array<number>): boolean;
							public cryptoAeadXChaCha20Poly1305IetfKeygen(param0: native.Array<number>): void;
							public cryptoAeadXChaCha20Poly1305IetfEncryptDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: native.Array<number>, param8: native.Array<number>, param9: native.Array<number>): boolean;
						}
						export class StateAES {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.AEAD.StateAES>;
							public arr: native.Array<number>;
							public constructor();
							public getFieldOrder(): java.util.List<string>;
						}
						export module StateAES {
							export class ByReference extends com.goterl.lazycode.lazysodium.interfaces.AEAD.StateAES {
								public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.AEAD.StateAES.ByReference>;
								public constructor();
							}
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class Auth {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Auth>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Auth interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
						});
						public constructor();
						public static HMACSHA512256_KEYBYTES: number;
						public static HMACSHA512_BYTES: number;
						public static KEYBYTES: number;
						public static HMACSHA256_BYTES: number;
						public static HMACSHA256_KEYBYTES: number;
						public static BYTES: number;
						public static HMACSHA512256_BYTES: number;
						public static HMACSHA512_KEYBYTES: number;
					}
					export module Auth {
						export class Checker extends com.goterl.lazycode.lazysodium.utils.BaseChecker {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Auth.Checker>;
							public constructor();
						}
						export class Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Auth.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Auth$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoAuthKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
								cryptoAuth(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
								cryptoAuthVerify(param0: string, param1: string, param2: com.goterl.lazycode.lazysodium.utils.Key): boolean;
								cryptoAuthHMACShaKeygen(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.Type): com.goterl.lazycode.lazysodium.utils.Key;
								cryptoAuthHMACSha(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.Type, param1: string, param2: com.goterl.lazycode.lazysodium.utils.Key): string;
								cryptoAuthHMACShaVerify(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.Type, param1: string, param2: string, param3: com.goterl.lazycode.lazysodium.utils.Key): boolean;
								cryptoAuthHMACShaInit(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: com.goterl.lazycode.lazysodium.utils.Key): boolean;
								cryptoAuthHMACShaUpdate(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: string): boolean;
								cryptoAuthHMACShaFinal(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256): string;
								cryptoAuthHMACShaInit(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: com.goterl.lazycode.lazysodium.utils.Key): boolean;
								cryptoAuthHMACShaUpdate(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: string): boolean;
								cryptoAuthHMACShaFinal(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512): string;
								cryptoAuthHMACShaInit(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: com.goterl.lazycode.lazysodium.utils.Key): boolean;
								cryptoAuthHMACShaUpdate(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: string): boolean;
								cryptoAuthHMACShaFinal(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256): string;
							});
							public constructor();
							public cryptoAuthHMACShaKeygen(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.Type): com.goterl.lazycode.lazysodium.utils.Key;
							public cryptoAuthHMACSha(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.Type, param1: string, param2: com.goterl.lazycode.lazysodium.utils.Key): string;
							public cryptoAuthKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
							public cryptoAuth(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
							public cryptoAuthHMACShaInit(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: com.goterl.lazycode.lazysodium.utils.Key): boolean;
							public cryptoAuthHMACShaFinal(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512): string;
							public cryptoAuthHMACShaVerify(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.Type, param1: string, param2: string, param3: com.goterl.lazycode.lazysodium.utils.Key): boolean;
							public cryptoAuthHMACShaInit(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: com.goterl.lazycode.lazysodium.utils.Key): boolean;
							public cryptoAuthVerify(param0: string, param1: string, param2: com.goterl.lazycode.lazysodium.utils.Key): boolean;
							public cryptoAuthHMACShaFinal(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256): string;
							public cryptoAuthHMACShaUpdate(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: string): boolean;
							public cryptoAuthHMACShaUpdate(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: string): boolean;
							public cryptoAuthHMACShaInit(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: com.goterl.lazycode.lazysodium.utils.Key): boolean;
							public cryptoAuthHMACShaUpdate(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: string): boolean;
							public cryptoAuthHMACShaFinal(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256): string;
						}
						export class Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Auth.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Auth$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoAuthKeygen(param0: native.Array<number>): void;
								cryptoAuth(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
								cryptoAuthVerify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
								cryptoAuthHMACSha256Keygen(param0: native.Array<number>): void;
								cryptoAuthHMACSha256(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
								cryptoAuthHMACSha256Verify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
								cryptoAuthHMACSha256Init(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: native.Array<number>, param2: number): boolean;
								cryptoAuthHMACSha256Update(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: native.Array<number>, param2: number): boolean;
								cryptoAuthHMACSha256Final(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: native.Array<number>): boolean;
								cryptoAuthHMACSha512Keygen(param0: native.Array<number>): void;
								cryptoAuthHMACSha512(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
								cryptoAuthHMACSha512Verify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
								cryptoAuthHMACSha512Init(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: native.Array<number>, param2: number): boolean;
								cryptoAuthHMACSha512Update(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: native.Array<number>, param2: number): boolean;
								cryptoAuthHMACSha512Final(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: native.Array<number>): boolean;
								cryptoAuthHMACSha512256Keygen(param0: native.Array<number>): void;
								cryptoAuthHMACSha512256(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
								cryptoAuthHMACSha512256Verify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
								cryptoAuthHMACSha512256Init(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: native.Array<number>, param2: number): boolean;
								cryptoAuthHMACSha512256Update(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: native.Array<number>, param2: number): boolean;
								cryptoAuthHMACSha512256Final(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: native.Array<number>): boolean;
							});
							public constructor();
							public cryptoAuthHMACSha512Verify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
							public cryptoAuthKeygen(param0: native.Array<number>): void;
							public cryptoAuthHMACSha512Final(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: native.Array<number>): boolean;
							public cryptoAuthHMACSha256Keygen(param0: native.Array<number>): void;
							public cryptoAuthHMACSha256Final(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: native.Array<number>): boolean;
							public cryptoAuthHMACSha512256(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
							public cryptoAuthVerify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
							public cryptoAuthHMACSha512256Final(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: native.Array<number>): boolean;
							public cryptoAuthHMACSha512256Keygen(param0: native.Array<number>): void;
							public cryptoAuthHMACSha512Keygen(param0: native.Array<number>): void;
							public cryptoAuthHMACSha512(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
							public cryptoAuthHMACSha256Verify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
							public cryptoAuth(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
							public cryptoAuthHMACSha512Init(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: native.Array<number>, param2: number): boolean;
							public cryptoAuthHMACSha512256Verify(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
							public cryptoAuthHMACSha256(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
							public cryptoAuthHMACSha256Update(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: native.Array<number>, param2: number): boolean;
							public cryptoAuthHMACSha256Init(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256, param1: native.Array<number>, param2: number): boolean;
							public cryptoAuthHMACSha512256Update(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: native.Array<number>, param2: number): boolean;
							public cryptoAuthHMACSha512Update(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512, param1: native.Array<number>, param2: number): boolean;
							public cryptoAuthHMACSha512256Init(param0: com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256, param1: native.Array<number>, param2: number): boolean;
						}
						export class StateHMAC256 {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256>;
							public ictx: com.goterl.lazycode.lazysodium.interfaces.Hash.State256;
							public octx: com.goterl.lazycode.lazysodium.interfaces.Hash.State256;
							public constructor();
							public getFieldOrder(): java.util.List<string>;
						}
						export module StateHMAC256 {
							export class ByReference extends com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256 {
								public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC256.ByReference>;
								public constructor();
							}
						}
						export class StateHMAC512 {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512>;
							public ictx: com.goterl.lazycode.lazysodium.interfaces.Hash.State512;
							public octx: com.goterl.lazycode.lazysodium.interfaces.Hash.State512;
							public constructor();
							public getFieldOrder(): java.util.List<string>;
						}
						export module StateHMAC512 {
							export class ByReference extends com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512 {
								public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512.ByReference>;
								public constructor();
							}
						}
						export class StateHMAC512256 {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256>;
							public ictx: com.goterl.lazycode.lazysodium.interfaces.Hash.State512;
							public octx: com.goterl.lazycode.lazysodium.interfaces.Hash.State512;
							public constructor();
							public getFieldOrder(): java.util.List<string>;
						}
						export module StateHMAC512256 {
							export class ByReference extends com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256 {
								public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Auth.StateHMAC512256.ByReference>;
								public constructor();
							}
						}
						export class Type {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Auth.Type>;
							public static SHA256: com.goterl.lazycode.lazysodium.interfaces.Auth.Type;
							public static SHA512: com.goterl.lazycode.lazysodium.interfaces.Auth.Type;
							public static SHA512256: com.goterl.lazycode.lazysodium.interfaces.Auth.Type;
							public static valueOf(param0: string): com.goterl.lazycode.lazysodium.interfaces.Auth.Type;
							public static values(): native.Array<com.goterl.lazycode.lazysodium.interfaces.Auth.Type>;
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class Base {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Base>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Base interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
							successful(param0: number): boolean;
							res(param0: number, param1: any): any;
							str(param0: native.Array<number>): string;
							str(param0: native.Array<number>, param1: java.nio.charset.Charset): string;
							bytes(param0: string): native.Array<number>;
							wrongLen(param0: native.Array<number>, param1: number): boolean;
							wrongLen(param0: number, param1: number): boolean;
							wrongLen(param0: number, param1: number): boolean;
							removeNulls(param0: native.Array<number>): native.Array<number>;
						});
						public constructor();
						public wrongLen(param0: number, param1: number): boolean;
						public str(param0: native.Array<number>): string;
						public wrongLen(param0: native.Array<number>, param1: number): boolean;
						public str(param0: native.Array<number>, param1: java.nio.charset.Charset): string;
						public res(param0: number, param1: any): any;
						public bytes(param0: string): native.Array<number>;
						public removeNulls(param0: native.Array<number>): native.Array<number>;
						public successful(param0: number): boolean;
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class Box {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Box>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Box interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
						});
						public constructor();
						public static CURVE25519XSALSA20POLY1305_BEFORENMBYTES: number;
						public static CURVE25519XSALSA20POLY1305_PUBLICKEYBYTES: number;
						public static CURVE25519XSALSA20POLY1305_SECRETKEYBYTES: number;
						public static MACBYTES: number;
						public static CURVE25519XSALSA20POLY1305_SEEDBYTES: number;
						public static BEFORENMBYTES: number;
						public static PUBLICKEYBYTES: number;
						public static NONCEBYTES: number;
						public static SEALBYTES: number;
						public static SEEDBYTES: number;
						public static CURVE25519XSALSA20POLY1305_MACBYTES: number;
						public static SECRETKEYBYTES: number;
						public static CURVE25519XSALSA20POLY1305_NONCEBYTES: number;
					}
					export module Box {
						export class Checker extends com.goterl.lazycode.lazysodium.utils.BaseChecker {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Box.Checker>;
							public constructor();
							public static checkMac(param0: number): boolean;
							public static checkBeforeNmBytes(param0: number): boolean;
							public static checkNonce(param0: number): boolean;
							public static checkPublicKey(param0: number): boolean;
							public static checkSeed(param0: number): boolean;
							public static checkSecretKey(param0: number): boolean;
						}
						export class Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Box.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Box$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoBoxKeypair(): com.goterl.lazycode.lazysodium.utils.KeyPair;
								cryptoBoxSeedKeypair(param0: native.Array<number>): com.goterl.lazycode.lazysodium.utils.KeyPair;
								cryptoBoxEasy(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.KeyPair): string;
								cryptoBoxOpenEasy(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.KeyPair): string;
								cryptoBoxBeforeNm(param0: native.Array<number>, param1: native.Array<number>): string;
								cryptoBoxBeforeNm(param0: com.goterl.lazycode.lazysodium.utils.KeyPair): string;
								cryptoBoxEasyAfterNm(param0: string, param1: native.Array<number>, param2: string): string;
								cryptoBoxOpenEasyAfterNm(param0: string, param1: native.Array<number>, param2: string): string;
								cryptoBoxDetachedAfterNm(param0: string, param1: native.Array<number>, param2: string): com.goterl.lazycode.lazysodium.utils.DetachedEncrypt;
								cryptoBoxOpenDetachedAfterNm(param0: com.goterl.lazycode.lazysodium.utils.DetachedEncrypt, param1: native.Array<number>, param2: string): com.goterl.lazycode.lazysodium.utils.DetachedDecrypt;
							});
							public constructor();
							public cryptoBoxOpenEasy(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.KeyPair): string;
							public cryptoBoxSeedKeypair(param0: native.Array<number>): com.goterl.lazycode.lazysodium.utils.KeyPair;
							public cryptoBoxBeforeNm(param0: com.goterl.lazycode.lazysodium.utils.KeyPair): string;
							public cryptoBoxOpenEasyAfterNm(param0: string, param1: native.Array<number>, param2: string): string;
							public cryptoBoxEasy(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.KeyPair): string;
							public cryptoBoxDetachedAfterNm(param0: string, param1: native.Array<number>, param2: string): com.goterl.lazycode.lazysodium.utils.DetachedEncrypt;
							public cryptoBoxEasyAfterNm(param0: string, param1: native.Array<number>, param2: string): string;
							public cryptoBoxOpenDetachedAfterNm(param0: com.goterl.lazycode.lazysodium.utils.DetachedEncrypt, param1: native.Array<number>, param2: string): com.goterl.lazycode.lazysodium.utils.DetachedDecrypt;
							public cryptoBoxKeypair(): com.goterl.lazycode.lazysodium.utils.KeyPair;
							public cryptoBoxBeforeNm(param0: native.Array<number>, param1: native.Array<number>): string;
						}
						export class Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Box.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Box$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoBoxKeypair(param0: native.Array<number>, param1: native.Array<number>): boolean;
								cryptoBoxSeedKeypair(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
								cryptoBoxEasy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>, param5: native.Array<number>): boolean;
								cryptoBoxOpenEasy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>, param5: native.Array<number>): boolean;
								cryptoBoxDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: native.Array<number>): boolean;
								cryptoBoxOpenDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>, param5: native.Array<number>, param6: native.Array<number>): boolean;
								cryptoBoxBeforeNm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
								cryptoBoxEasyAfterNm(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
								cryptoBoxOpenEasyAfterNm(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
								cryptoBoxDetachedAfterNm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): boolean;
								cryptoBoxOpenDetachedAfterNm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): boolean;
								cryptoBoxSeal(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
								cryptoBoxSealOpen(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							});
							public constructor();
							public cryptoBoxEasy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>, param5: native.Array<number>): boolean;
							public cryptoBoxOpenDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>, param5: native.Array<number>, param6: native.Array<number>): boolean;
							public cryptoBoxOpenEasyAfterNm(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							public cryptoBoxDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>, param6: native.Array<number>): boolean;
							public cryptoBoxKeypair(param0: native.Array<number>, param1: native.Array<number>): boolean;
							public cryptoBoxEasyAfterNm(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							public cryptoBoxDetachedAfterNm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): boolean;
							public cryptoBoxSeal(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
							public cryptoBoxSealOpen(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							public cryptoBoxBeforeNm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
							public cryptoBoxSeedKeypair(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
							public cryptoBoxOpenEasy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>, param5: native.Array<number>): boolean;
							public cryptoBoxOpenDetachedAfterNm(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): boolean;
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class DiffieHellman {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.DiffieHellman>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.DiffieHellman interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
						});
						public constructor();
						public static SCALARMULT_CURVE25519_BYTES: number;
						public static SCALARMULT_SCALARBYTES: number;
						public static SCALARMULT_BYTES: number;
						public static SCALARMULT_CURVE25519_SCALARBYTES: number;
					}
					export module DiffieHellman {
						export class Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.DiffieHellman.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.DiffieHellman$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoScalarMultBase(param0: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.Key;
								cryptoScalarMult(param0: com.goterl.lazycode.lazysodium.utils.Key, param1: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.Key;
							});
							public constructor();
							public cryptoScalarMult(param0: com.goterl.lazycode.lazysodium.utils.Key, param1: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.Key;
							public cryptoScalarMultBase(param0: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.Key;
						}
						export class Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.DiffieHellman.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.DiffieHellman$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoScalarMultBase(param0: native.Array<number>, param1: native.Array<number>): boolean;
								cryptoScalarMult(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
							});
							public constructor();
							public cryptoScalarMultBase(param0: native.Array<number>, param1: native.Array<number>): boolean;
							public cryptoScalarMult(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class GenericHash {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.GenericHash>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.GenericHash interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
						});
						public constructor();
						public static BLAKE2B_KEYBYTES: number;
						public static BLAKE2B_SALTBYTES: number;
						public static BYTES_MIN: number;
						public static BLAKE2B_BYTES_MAX: number;
						public static BLAKE2B_KEYBYTES_MAX: number;
						public static BYTES: number;
						public static BLAKE2B_PERSONALBYTES: number;
						public static BYTES_MAX: number;
						public static BLAKE2B_BYTES: number;
						public static BLAKE2B_BYTES_MIN: number;
						public static KEYBYTES: number;
						public static KEYBYTES_MAX: number;
						public static BLAKE2B_KEYBYTES_MIN: number;
					}
					export module GenericHash {
						export class Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.GenericHash.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.GenericHash$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoGenericHashKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
								cryptoGenericHashKeygen(param0: number): com.goterl.lazycode.lazysodium.utils.Key;
								cryptoGenericHash(param0: string): string;
								cryptoGenericHash(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
								cryptoGenericHashInit(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: number): boolean;
								cryptoGenericHashUpdate(param0: native.Array<number>, param1: string): boolean;
								cryptoGenericHashFinal(param0: native.Array<number>, param1: number): string;
							});
							public constructor();
							public cryptoGenericHashKeygen(param0: number): com.goterl.lazycode.lazysodium.utils.Key;
							public cryptoGenericHashKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
							public cryptoGenericHash(param0: string): string;
							public cryptoGenericHashFinal(param0: native.Array<number>, param1: number): string;
							public cryptoGenericHashInit(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: number): boolean;
							public cryptoGenericHash(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
							public cryptoGenericHashUpdate(param0: native.Array<number>, param1: string): boolean;
						}
						export class Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.GenericHash.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.GenericHash$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoGenericHashKeygen(param0: native.Array<number>): void;
								cryptoGenericHash(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number): boolean;
								cryptoGenericHash(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number): boolean;
								cryptoGenericHashInit(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: number): boolean;
								cryptoGenericHashInit(param0: native.Array<number>, param1: number): boolean;
								cryptoGenericHashUpdate(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
								cryptoGenericHashFinal(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
								cryptoGenericHashStateBytes(): number;
							});
							public constructor();
							public cryptoGenericHashInit(param0: native.Array<number>, param1: number): boolean;
							public cryptoGenericHash(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number): boolean;
							public cryptoGenericHashUpdate(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
							public cryptoGenericHashInit(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: number): boolean;
							public cryptoGenericHashKeygen(param0: native.Array<number>): void;
							public cryptoGenericHash(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number): boolean;
							public cryptoGenericHashFinal(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
							public cryptoGenericHashStateBytes(): number;
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class Hash {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Hash>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Hash interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
						});
						public constructor();
						public static BYTES: number;
						public static SHA512_BYTES: number;
						public static SHA256_BYTES: number;
					}
					export module Hash {
						export class Checker extends com.goterl.lazycode.lazysodium.utils.BaseChecker {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Hash.Checker>;
							public constructor();
						}
						export class Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Hash.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Hash$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoHashSha256(param0: string): string;
								cryptoHashSha512(param0: string): string;
								cryptoHashSha256Init(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256): boolean;
								cryptoHashSha256Update(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256, param1: string): boolean;
								cryptoHashSha256Final(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256): string;
								cryptoHashSha512Init(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512): boolean;
								cryptoHashSha512Update(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512, param1: string): boolean;
								cryptoHashSha512Final(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512): string;
							});
							public constructor();
							public cryptoHashSha512Update(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512, param1: string): boolean;
							public cryptoHashSha512Init(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512): boolean;
							public cryptoHashSha256Update(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256, param1: string): boolean;
							public cryptoHashSha256(param0: string): string;
							public cryptoHashSha256Final(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256): string;
							public cryptoHashSha256Init(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256): boolean;
							public cryptoHashSha512Final(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512): string;
							public cryptoHashSha512(param0: string): string;
						}
						export class Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Hash.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Hash$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoHashSha256(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
								cryptoHashSha512(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
								cryptoHashSha256Init(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256): boolean;
								cryptoHashSha256Update(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256, param1: native.Array<number>, param2: number): boolean;
								cryptoHashSha256Final(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256, param1: native.Array<number>): boolean;
								cryptoHashSha512Init(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512): boolean;
								cryptoHashSha512Update(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512, param1: native.Array<number>, param2: number): boolean;
								cryptoHashSha512Final(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512, param1: native.Array<number>): boolean;
							});
							public constructor();
							public cryptoHashSha256Update(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256, param1: native.Array<number>, param2: number): boolean;
							public cryptoHashSha256Final(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256, param1: native.Array<number>): boolean;
							public cryptoHashSha512(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
							public cryptoHashSha512Update(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512, param1: native.Array<number>, param2: number): boolean;
							public cryptoHashSha512Init(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512): boolean;
							public cryptoHashSha256(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
							public cryptoHashSha512Final(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State512, param1: native.Array<number>): boolean;
							public cryptoHashSha256Init(param0: com.goterl.lazycode.lazysodium.interfaces.Hash.State256): boolean;
						}
						export class State256 {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Hash.State256>;
							public state: native.Array<number>;
							public count: number;
							public buf: native.Array<number>;
							public constructor();
							public getFieldOrder(): java.util.List<string>;
						}
						export module State256 {
							export class ByReference extends com.goterl.lazycode.lazysodium.interfaces.Hash.State256 {
								public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Hash.State256.ByReference>;
								public constructor();
							}
						}
						export class State512 {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Hash.State512>;
							public state: native.Array<number>;
							public count: native.Array<number>;
							public buf: native.Array<number>;
							public constructor();
							public getFieldOrder(): java.util.List<string>;
						}
						export module State512 {
							export class ByReference extends com.goterl.lazycode.lazysodium.interfaces.Hash.State512 {
								public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Hash.State512.ByReference>;
								public constructor();
							}
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class Helpers {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Helpers>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Helpers interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
						});
						public constructor();
					}
					export module Helpers {
						export class Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Helpers.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Helpers$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								sodiumBin2Hex(param0: native.Array<number>): string;
								sodiumHex2Bin(param0: string): native.Array<number>;
							});
							public constructor();
							public sodiumHex2Bin(param0: string): native.Array<number>;
							public sodiumBin2Hex(param0: native.Array<number>): string;
						}
						export class Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Helpers.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Helpers$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								sodiumInit(): number;
							});
							public constructor();
							public sodiumInit(): number;
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class KeyDerivation {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.KeyDerivation>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.KeyDerivation interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
						});
						public constructor();
						public static BLAKE2B_BYTES_MIN: number;
						public static BYTES_MIN: number;
						public static CONTEXT_BYTES: number;
						public static BLAKE2B_BYTES_MAX: number;
						public static MASTER_KEY_BYTES: number;
						public static BYTES_MAX: number;
					}
					export module KeyDerivation {
						export class Checker extends com.goterl.lazycode.lazysodium.utils.BaseChecker {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.KeyDerivation.Checker>;
							public constructor();
							public static masterKeyIsCorrect(param0: number): boolean;
							public static subKeyIsCorrect(param0: number): boolean;
							public static contextIsCorrect(param0: number): boolean;
						}
						export class Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.KeyDerivation.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.KeyDerivation$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoKdfKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
								cryptoKdfDeriveFromKey(param0: number, param1: number, param2: string, param3: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.Key;
							});
							public constructor();
							public cryptoKdfKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
							public cryptoKdfDeriveFromKey(param0: number, param1: number, param2: string, param3: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.Key;
						}
						export class Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.KeyDerivation.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.KeyDerivation$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoKdfKeygen(param0: native.Array<number>): void;
								cryptoKdfDeriveFromKey(param0: native.Array<number>, param1: number, param2: number, param3: native.Array<number>, param4: native.Array<number>): number;
							});
							public constructor();
							public cryptoKdfKeygen(param0: native.Array<number>): void;
							public cryptoKdfDeriveFromKey(param0: native.Array<number>, param1: number, param2: number, param3: native.Array<number>, param4: native.Array<number>): number;
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class KeyExchange {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.KeyExchange>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.KeyExchange interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
						});
						public constructor();
						public static PUBLICKEYBYTES: number;
						public static SESSIONKEYBYTES: number;
						public static SEEDBYTES: number;
						public static SECRETKEYBYTES: number;
						public static PRIMITIVE: string;
					}
					export module KeyExchange {
						export class Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.KeyExchange.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.KeyExchange$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoKxKeypair(): com.goterl.lazycode.lazysodium.utils.KeyPair;
								cryptoKxKeypair(param0: native.Array<number>): com.goterl.lazycode.lazysodium.utils.KeyPair;
								cryptoKxClientSessionKeys(param0: com.goterl.lazycode.lazysodium.utils.Key, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.SessionPair;
								cryptoKxClientSessionKeys(param0: com.goterl.lazycode.lazysodium.utils.KeyPair, param1: com.goterl.lazycode.lazysodium.utils.KeyPair): com.goterl.lazycode.lazysodium.utils.SessionPair;
								cryptoKxServerSessionKeys(param0: com.goterl.lazycode.lazysodium.utils.Key, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.SessionPair;
								cryptoKxServerSessionKeys(param0: com.goterl.lazycode.lazysodium.utils.KeyPair, param1: com.goterl.lazycode.lazysodium.utils.KeyPair): com.goterl.lazycode.lazysodium.utils.SessionPair;
							});
							public constructor();
							public cryptoKxKeypair(): com.goterl.lazycode.lazysodium.utils.KeyPair;
							public cryptoKxServerSessionKeys(param0: com.goterl.lazycode.lazysodium.utils.Key, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.SessionPair;
							public cryptoKxKeypair(param0: native.Array<number>): com.goterl.lazycode.lazysodium.utils.KeyPair;
							public cryptoKxServerSessionKeys(param0: com.goterl.lazycode.lazysodium.utils.KeyPair, param1: com.goterl.lazycode.lazysodium.utils.KeyPair): com.goterl.lazycode.lazysodium.utils.SessionPair;
							public cryptoKxClientSessionKeys(param0: com.goterl.lazycode.lazysodium.utils.Key, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.SessionPair;
							public cryptoKxClientSessionKeys(param0: com.goterl.lazycode.lazysodium.utils.KeyPair, param1: com.goterl.lazycode.lazysodium.utils.KeyPair): com.goterl.lazycode.lazysodium.utils.SessionPair;
						}
						export class Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.KeyExchange.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.KeyExchange$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoKxKeypair(param0: native.Array<number>, param1: native.Array<number>): boolean;
								cryptoKxSeedKeypair(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
								cryptoKxClientSessionKeys(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>): boolean;
								cryptoKxServerSessionKeys(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>): boolean;
							});
							public constructor();
							public cryptoKxClientSessionKeys(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>): boolean;
							public cryptoKxKeypair(param0: native.Array<number>, param1: native.Array<number>): boolean;
							public cryptoKxSeedKeypair(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
							public cryptoKxServerSessionKeys(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>): boolean;
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class Padding {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Padding>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Padding interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
						});
						public constructor();
					}
					export module Padding {
						export class Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Padding.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Padding$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
							});
							public constructor();
						}
						export class Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Padding.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Padding$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								sodiumPad(param0: number, param1: native.Array<string>, param2: number, param3: number, param4: number): boolean;
								sodiumUnpad(param0: number, param1: native.Array<string>, param2: number, param3: number): boolean;
							});
							public constructor();
							public sodiumUnpad(param0: number, param1: native.Array<string>, param2: number, param3: number): boolean;
							public sodiumPad(param0: number, param1: native.Array<string>, param2: number, param3: number, param4: number): boolean;
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class PwHash {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.PwHash>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.PwHash interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
							<clinit>(): void;
						});
						public constructor();
						public static ARGON2ID_MEMLIMIT_MAX: number;
						public static MEMLIMIT_SENSITIVE: com.sun.jna.NativeLong;
						public static PASSWD_MIN: number;
						public static BYTES_MIN: number;
						public static ARGON2ID_OPSLIMIT_MIN: number;
						public static ARGON2ID_BYTES_MAX: number;
						public static OPSLIMIT_MIN: number;
						public static OPSLIMIT_MODERATE: number;
						public static ARGON2ID_SALTBYTES: number;
						public static ARGON2ID_MEMLIMIT_SENSITIVE: number;
						public static MEMLIMIT_INTERACTIVE: com.sun.jna.NativeLong;
						public static ARGON2ID_MEMLIMIT_MIN: number;
						public static ARGON2ID_STR_BYTES: number;
						public static ARGON2ID_OPSLIMIT_MAX: number;
						public static ARGON2ID_OPSLIMIT_MODERATE: number;
						public static ARGON2ID_OPSLIMIT_SENSITIVE: number;
						public static MEMLIMIT_MIN: com.sun.jna.NativeLong;
						public static ARGON2ID_PASSWD_MIN: number;
						public static SALTBYTES: number;
						public static MEMLIMIT_MAX: com.sun.jna.NativeLong;
						public static ARGON2ID_MEMLIMIT_MODERATE: number;
						public static BYTES_MAX: number;
						public static STR_BYTES: number;
						public static ARGON2ID_PASSWD_MAX: number;
						public static OPSLIMIT_INTERACTIVE: number;
						public static PASSWD_MAX: number;
						public static OPSLIMIT_SENSITIVE: number;
						public static ARGON2ID_BYTES_MIN: number;
						public static OPSLIMIT_MAX: number;
						public static ARGON2ID_MEMLIMIT_INTERACTIVE: number;
						public static ARGON2ID_OPSLIMIT_INTERACTIVE: number;
						public static MEMLIMIT_MODERATE: com.sun.jna.NativeLong;
					}
					export module PwHash {
						export class Alg {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.PwHash.Alg>;
							public static PWHASH_ALG_ARGON2I13: com.goterl.lazycode.lazysodium.interfaces.PwHash.Alg;
							public static PWHASH_ALG_ARGON2ID13: com.goterl.lazycode.lazysodium.interfaces.PwHash.Alg;
							public static valueOf(param0: string): com.goterl.lazycode.lazysodium.interfaces.PwHash.Alg;
							public static getDefault(): com.goterl.lazycode.lazysodium.interfaces.PwHash.Alg;
							public static valueOf(param0: number): com.goterl.lazycode.lazysodium.interfaces.PwHash.Alg;
							public getValue(): number;
							public static values(): native.Array<com.goterl.lazycode.lazysodium.interfaces.PwHash.Alg>;
						}
						export class Checker extends com.goterl.lazycode.lazysodium.utils.BaseChecker {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.PwHash.Checker>;
							public constructor();
							public static opsLimitIsCorrect(param0: number): boolean;
							public static checkAll(param0: number, param1: number, param2: number, param3: com.sun.jna.NativeLong): boolean;
							public static memLimitIsCorrect(param0: com.sun.jna.NativeLong): boolean;
							public static saltIsCorrect(param0: number): boolean;
							public static passwordIsCorrect(param0: number): boolean;
						}
						export class Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.PwHash.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.PwHash$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoPwHash(param0: string, param1: number, param2: native.Array<number>, param3: number, param4: com.sun.jna.NativeLong, param5: com.goterl.lazycode.lazysodium.interfaces.PwHash.Alg): string;
								cryptoPwHashStr(param0: string, param1: number, param2: com.sun.jna.NativeLong): string;
								cryptoPwHashStrRemoveNulls(param0: string, param1: number, param2: com.sun.jna.NativeLong): string;
								cryptoPwHashStrVerify(param0: string, param1: string): boolean;
							});
							public constructor();
							public cryptoPwHashStrVerify(param0: string, param1: string): boolean;
							public cryptoPwHashStr(param0: string, param1: number, param2: com.sun.jna.NativeLong): string;
							public cryptoPwHash(param0: string, param1: number, param2: native.Array<number>, param3: number, param4: com.sun.jna.NativeLong, param5: com.goterl.lazycode.lazysodium.interfaces.PwHash.Alg): string;
							public cryptoPwHashStrRemoveNulls(param0: string, param1: number, param2: com.sun.jna.NativeLong): string;
						}
						export class Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.PwHash.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.PwHash$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoPwHash(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: com.sun.jna.NativeLong, param7: com.goterl.lazycode.lazysodium.interfaces.PwHash.Alg): boolean;
								cryptoPwHashStr(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: number, param4: com.sun.jna.NativeLong): boolean;
								cryptoPwHashStrVerify(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
								cryptoPwHashStrNeedsRehash(param0: native.Array<number>, param1: number, param2: com.sun.jna.NativeLong): boolean;
							});
							public constructor();
							public cryptoPwHashStr(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: number, param4: com.sun.jna.NativeLong): boolean;
							public cryptoPwHashStrVerify(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
							public cryptoPwHashStrNeedsRehash(param0: native.Array<number>, param1: number, param2: com.sun.jna.NativeLong): boolean;
							public cryptoPwHash(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: com.sun.jna.NativeLong, param7: com.goterl.lazycode.lazysodium.interfaces.PwHash.Alg): boolean;
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class Random {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Random>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Random interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
							randomBytesRandom(): number;
							randomBytesUniform(param0: number): number;
							randomBytesBuf(param0: number): native.Array<number>;
							randomBytesDeterministic(param0: number, param1: native.Array<number>): native.Array<number>;
							nonce(param0: number): native.Array<number>;
						});
						public constructor();
						public randomBytesBuf(param0: number): native.Array<number>;
						public randomBytesRandom(): number;
						public randomBytesUniform(param0: number): number;
						public randomBytesDeterministic(param0: number, param1: native.Array<number>): native.Array<number>;
						public nonce(param0: number): native.Array<number>;
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class Scrypt {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Scrypt>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Scrypt interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
						});
						public constructor();
						public static SCRYPTSALSA208SHA256_OPSLIMIT_SENSITIVE: number;
						public static SCRYPTSALSA208SHA256_STRBYTES: number;
						public static SCRYPTSALSA208SHA256_OPSLIMIT_MIN: number;
						public static SCRYPTSALSA208SHA256_MEMLIMIT_MAX: number;
						public static SCRYPTSALSA208SHA256_MEMLIMIT_SENSITIVE: number;
						public static SCRYPTSALSA208SHA256_SALT_BYTES: number;
						public static SCRYPTSALSA208SHA256_PASSWD_MAX: number;
						public static SCRYPTSALSA208SHA256_BYTES_MIN: number;
						public static SCRYPTSALSA208SHA256_BYTES_MAX: number;
						public static SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE: number;
						public static SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE: number;
						public static SCRYPTSALSA208SHA256_MEMLIMIT_MIN: number;
						public static SCRYPTSALSA208SHA256_OPSLIMIT_MAX: number;
						public static SCRYPTSALSA208SHA256_PASSWD_MIN: number;
					}
					export module Scrypt {
						export class Checker extends com.goterl.lazycode.lazysodium.utils.BaseChecker {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Scrypt.Checker>;
							public constructor();
							public static checkOpsLimitScrypt(param0: number): boolean;
							public static checkMemLimitScrypt(param0: number): boolean;
							public static checkAllScrypt(param0: number, param1: number, param2: number, param3: number): boolean;
						}
						export class Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Scrypt.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Scrypt$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoPwHashScryptSalsa208Sha256(param0: string, param1: native.Array<number>, param2: number, param3: number): string;
								cryptoPwHashScryptSalsa208Sha256Str(param0: string, param1: number, param2: number): string;
								cryptoPwHashScryptSalsa208Sha256StrVerify(param0: string, param1: string): boolean;
							});
							public constructor();
							public cryptoPwHashScryptSalsa208Sha256Str(param0: string, param1: number, param2: number): string;
							public cryptoPwHashScryptSalsa208Sha256StrVerify(param0: string, param1: string): boolean;
							public cryptoPwHashScryptSalsa208Sha256(param0: string, param1: native.Array<number>, param2: number, param3: number): string;
						}
						export class Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Scrypt.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Scrypt$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoPwHashScryptSalsa208Sha256(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: number): boolean;
								cryptoPwHashScryptSalsa208Sha256Str(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: number, param4: number): boolean;
								cryptoPwHashScryptSalsa208Sha256StrVerify(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
								cryptoPwHashScryptSalsa208Sha256Ll(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number, param4: number, param5: number, param6: number, param7: native.Array<number>, param8: number): boolean;
								cryptoPwHashScryptSalsa208Sha256StrNeedsRehash(param0: native.Array<number>, param1: number, param2: number): boolean;
							});
							public constructor();
							public cryptoPwHashScryptSalsa208Sha256Str(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: number, param4: number): boolean;
							public cryptoPwHashScryptSalsa208Sha256(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: number, param6: number): boolean;
							public cryptoPwHashScryptSalsa208Sha256StrVerify(param0: native.Array<number>, param1: native.Array<number>, param2: number): boolean;
							public cryptoPwHashScryptSalsa208Sha256StrNeedsRehash(param0: native.Array<number>, param1: number, param2: number): boolean;
							public cryptoPwHashScryptSalsa208Sha256Ll(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: number, param4: number, param5: number, param6: number, param7: native.Array<number>, param8: number): boolean;
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class SecretBox {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.SecretBox>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.SecretBox interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
						});
						public constructor();
						public static NONCEBYTES: number;
						public static KEYBYTES: number;
						public static MACBYTES: number;
						public static XSALSA20POLY1305_KEYBYTES: number;
						public static XSALSA20POLY1305_MACBYTES: number;
						public static XSALSA20POLY1305_NONCEBYTES: number;
					}
					export module SecretBox {
						export class Checker extends com.goterl.lazycode.lazysodium.utils.BaseChecker {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.SecretBox.Checker>;
							public constructor();
							public static checkKeyLen(param0: number): boolean;
							public static checkNonceLen(param0: number): boolean;
							public static checkMacLen(param0: number): boolean;
						}
						export class Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.SecretBox.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.SecretBox$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoSecretBoxKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
								cryptoSecretBoxEasy(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key): string;
								cryptoSecretBoxOpenEasy(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key): string;
								cryptoSecretBoxDetached(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.DetachedEncrypt;
								cryptoSecretBoxOpenDetached(param0: com.goterl.lazycode.lazysodium.utils.DetachedEncrypt, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key): string;
							});
							public constructor();
							public cryptoSecretBoxOpenDetached(param0: com.goterl.lazycode.lazysodium.utils.DetachedEncrypt, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key): string;
							public cryptoSecretBoxEasy(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key): string;
							public cryptoSecretBoxOpenEasy(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key): string;
							public cryptoSecretBoxDetached(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.DetachedEncrypt;
							public cryptoSecretBoxKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
						}
						export class Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.SecretBox.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.SecretBox$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoSecretBoxKeygen(param0: native.Array<number>): void;
								cryptoSecretBoxEasy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
								cryptoSecretBoxOpenEasy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
								cryptoSecretBoxDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): boolean;
								cryptoSecretBoxOpenDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): boolean;
							});
							public constructor();
							public cryptoSecretBoxEasy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							public cryptoSecretBoxOpenEasy(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							public cryptoSecretBoxOpenDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): boolean;
							public cryptoSecretBoxDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>, param5: native.Array<number>): boolean;
							public cryptoSecretBoxKeygen(param0: native.Array<number>): void;
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class SecretStream {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.SecretStream>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.SecretStream interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
						});
						public constructor();
						public static XCHACHA20POLY1305_TAG_FINAL: number;
						public static HEADERBYTES: number;
						public static CHACHA20_IETF_NONCEBYTES: number;
						public static TAG_FINAL: number;
						public static MESSAGEBYTES_MAX: number;
						public static TAG_MESSAGE: number;
						public static XCHACHA20POLY1305_TAG_REKEY: number;
						public static NONCEBYTES: number;
						public static KEYBYTES: number;
						public static ABYTES: number;
						public static XCHACHA20POLY1305_TAG_MESSAGE: number;
						public static TAG_PUSH: number;
						public static XCHACHA20POLY1305_TAG_PUSH: number;
						public static TAG_REKEY: number;
					}
					export module SecretStream {
						export class Checker extends com.goterl.lazycode.lazysodium.utils.BaseChecker {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.SecretStream.Checker>;
							public constructor();
							public static headerCheck(param0: number): boolean;
						}
						export class Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.SecretStream.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.SecretStream$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoSecretStreamKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
								cryptoSecretStreamInitPush(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.interfaces.SecretStream.State;
								cryptoSecretStreamPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: string, param2: number): string;
								cryptoSecretStreamInitPull(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.interfaces.SecretStream.State;
								cryptoSecretStreamPull(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: string, param2: native.Array<number>): string;
								cryptoSecretStreamRekey(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State): void;
							});
							public constructor();
							public cryptoSecretStreamKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
							public cryptoSecretStreamInitPush(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.interfaces.SecretStream.State;
							public cryptoSecretStreamPull(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: string, param2: native.Array<number>): string;
							public cryptoSecretStreamInitPull(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.interfaces.SecretStream.State;
							public cryptoSecretStreamRekey(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State): void;
							public cryptoSecretStreamPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: string, param2: number): string;
						}
						export class Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.SecretStream.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.SecretStream$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoSecretStreamKeygen(param0: native.Array<number>): void;
								cryptoSecretStreamInitPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>): boolean;
								cryptoSecretStreamPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: number): boolean;
								cryptoSecretStreamPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: number): boolean;
								cryptoSecretStreamPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: number): boolean;
								cryptoSecretStreamInitPull(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>): boolean;
								cryptoSecretStreamPull(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: number): boolean;
								cryptoSecretStreamPull(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number): boolean;
								cryptoSecretStreamRekey(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State): void;
							});
							public constructor();
							public cryptoSecretStreamPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: number): boolean;
							public cryptoSecretStreamInitPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>): boolean;
							public cryptoSecretStreamInitPull(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>): boolean;
							public cryptoSecretStreamPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number, param5: native.Array<number>, param6: number, param7: number): boolean;
							public cryptoSecretStreamPull(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: number): boolean;
							public cryptoSecretStreamKeygen(param0: native.Array<number>): void;
							public cryptoSecretStreamRekey(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State): void;
							public cryptoSecretStreamPush(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: number): boolean;
							public cryptoSecretStreamPull(param0: com.goterl.lazycode.lazysodium.interfaces.SecretStream.State, param1: native.Array<number>, param2: native.Array<number>, param3: native.Array<number>, param4: native.Array<number>, param5: number, param6: native.Array<number>, param7: number): boolean;
						}
						export class State {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.SecretStream.State>;
							public k: native.Array<number>;
							public nonce: native.Array<number>;
							public _pad: native.Array<number>;
							public constructor();
							public getFieldOrder(): java.util.List<string>;
						}
						export module State {
							export class ByReference extends com.goterl.lazycode.lazysodium.interfaces.SecretStream.State {
								public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.SecretStream.State.ByReference>;
								public constructor();
							}
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class SecureMemory {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.SecureMemory>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.SecureMemory interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
						});
						public constructor();
					}
					export module SecureMemory {
						export class Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.SecureMemory.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.SecureMemory$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
							});
							public constructor();
						}
						export class Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.SecureMemory.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.SecureMemory$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								sodiumMemZero(param0: native.Array<number>, param1: number): boolean;
								sodiumMLock(param0: native.Array<number>, param1: number): boolean;
								sodiumMUnlock(param0: native.Array<number>, param1: number): boolean;
								sodiumMalloc(param0: number): com.sun.jna.Pointer;
								sodiumAllocArray(param0: number, param1: number): com.sun.jna.Pointer;
								sodiumFree(param0: com.sun.jna.Pointer): void;
								sodiumMProtectNoAccess(param0: com.sun.jna.Pointer): boolean;
								sodiumMProtectReadOnly(param0: com.sun.jna.Pointer): boolean;
								sodiumMProtectReadWrite(param0: com.sun.jna.Pointer): boolean;
							});
							public constructor();
							public sodiumMLock(param0: native.Array<number>, param1: number): boolean;
							public sodiumMemZero(param0: native.Array<number>, param1: number): boolean;
							public sodiumMProtectReadWrite(param0: com.sun.jna.Pointer): boolean;
							public sodiumMProtectReadOnly(param0: com.sun.jna.Pointer): boolean;
							public sodiumMUnlock(param0: native.Array<number>, param1: number): boolean;
							public sodiumFree(param0: com.sun.jna.Pointer): void;
							public sodiumAllocArray(param0: number, param1: number): com.sun.jna.Pointer;
							public sodiumMalloc(param0: number): com.sun.jna.Pointer;
							public sodiumMProtectNoAccess(param0: com.sun.jna.Pointer): boolean;
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class ShortHash {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.ShortHash>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.ShortHash interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
						});
						public constructor();
						public static KEYBYTES: number;
						public static SIPHASHX24_KEYBYTES: number;
						public static BYTES: number;
						public static SIPHASH24_KEYBYTES: number;
						public static SIPHASHX24_BYTES: number;
						public static SIPHASH24_BYTES: number;
					}
					export module ShortHash {
						export class Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.ShortHash.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.ShortHash$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoShortHashKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
								cryptoShortHash(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
							});
							public constructor();
							public cryptoShortHashKeygen(): com.goterl.lazycode.lazysodium.utils.Key;
							public cryptoShortHash(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
						}
						export class Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.ShortHash.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.ShortHash$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoShortHash(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
								cryptoShortHashKeygen(param0: native.Array<number>): void;
							});
							public constructor();
							public cryptoShortHashKeygen(param0: native.Array<number>): void;
							public cryptoShortHash(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class Sign {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Sign>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Sign interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
						});
						public constructor();
						public static ED25519_SEEDBYTES: number;
						public static CURVE25519_PUBLICKEYBYTES: number;
						public static ED25519_BYTES: number;
						public static PUBLICKEYBYTES: number;
						public static ED25519_MESSAGEBYTES_MAX: number;
						public static CURVE25519_SECRETKEYBYTES: number;
						public static SEEDBYTES: number;
						public static BYTES: number;
						public static ED25519_PUBLICKEYBYTES: number;
						public static SECRETKEYBYTES: number;
						public static MESSAGEBYTES_MAX: number;
						public static ED25519_SECRETKEYBYTES: number;
					}
					export module Sign {
						export class Checker extends com.goterl.lazycode.lazysodium.utils.BaseChecker {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Sign.Checker>;
							public constructor();
						}
						export class Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Sign.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Sign$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoSignKeypair(): com.goterl.lazycode.lazysodium.utils.KeyPair;
								cryptoSignSeedKeypair(param0: native.Array<number>): com.goterl.lazycode.lazysodium.utils.KeyPair;
								cryptoSignSecretKeyPair(param0: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.KeyPair;
								cryptoSign(param0: string, param1: string): string;
								cryptoSignOpen(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
								cryptoSignDetached(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
								cryptoSignVerifyDetached(param0: string, param1: string, param2: com.goterl.lazycode.lazysodium.utils.Key): boolean;
								convertKeyPairEd25519ToCurve25519(param0: com.goterl.lazycode.lazysodium.utils.KeyPair): com.goterl.lazycode.lazysodium.utils.KeyPair;
							});
							public constructor();
							public cryptoSignDetached(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
							public cryptoSignSeedKeypair(param0: native.Array<number>): com.goterl.lazycode.lazysodium.utils.KeyPair;
							public cryptoSignVerifyDetached(param0: string, param1: string, param2: com.goterl.lazycode.lazysodium.utils.Key): boolean;
							public cryptoSign(param0: string, param1: string): string;
							public cryptoSignSecretKeyPair(param0: com.goterl.lazycode.lazysodium.utils.Key): com.goterl.lazycode.lazysodium.utils.KeyPair;
							public cryptoSignOpen(param0: string, param1: com.goterl.lazycode.lazysodium.utils.Key): string;
							public cryptoSignKeypair(): com.goterl.lazycode.lazysodium.utils.KeyPair;
							public convertKeyPairEd25519ToCurve25519(param0: com.goterl.lazycode.lazysodium.utils.KeyPair): com.goterl.lazycode.lazysodium.utils.KeyPair;
						}
						export class Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Sign.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Sign$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoSignKeypair(param0: native.Array<number>, param1: native.Array<number>): boolean;
								cryptoSignSeedKeypair(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
								cryptoSign(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>): boolean;
								cryptoSignOpen(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>): boolean;
								cryptoSignDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>): boolean;
								cryptoSignVerifyDetached(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
								convertPublicKeyEd25519ToCurve25519(param0: native.Array<number>, param1: native.Array<number>): boolean;
								convertSecretKeyEd25519ToCurve25519(param0: native.Array<number>, param1: native.Array<number>): boolean;
								cryptoSignEd25519SkToSeed(param0: native.Array<number>, param1: native.Array<number>): boolean;
								cryptoSignEd25519SkToPk(param0: native.Array<number>, param1: native.Array<number>): boolean;
							});
							public constructor();
							public convertPublicKeyEd25519ToCurve25519(param0: native.Array<number>, param1: native.Array<number>): boolean;
							public cryptoSignOpen(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>): boolean;
							public cryptoSignDetached(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>): boolean;
							public cryptoSignVerifyDetached(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>): boolean;
							public cryptoSignEd25519SkToSeed(param0: native.Array<number>, param1: native.Array<number>): boolean;
							public cryptoSignSeedKeypair(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>): boolean;
							public cryptoSign(param0: native.Array<number>, param1: native.Array<number>, param2: native.Array<number>, param3: number, param4: native.Array<number>): boolean;
							public convertSecretKeyEd25519ToCurve25519(param0: native.Array<number>, param1: native.Array<number>): boolean;
							public cryptoSignEd25519SkToPk(param0: native.Array<number>, param1: native.Array<number>): boolean;
							public cryptoSignKeypair(param0: native.Array<number>, param1: native.Array<number>): boolean;
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class Stream {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Stream>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Stream interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
						});
						public constructor();
						public static CHACHA20_IETF_MESSAGEBYTES_MAX: number;
						public static SALSA20_NONCEBYTES: number;
						public static SALSA20_MESSAGEBYTES_MAX: number;
						public static CHACHA20_MESSAGEBYTES_MAX: number;
						public static CHACHA20_IETF_NONCEBYTES: number;
						public static XSALSA20_KEYBYTES: number;
						public static CHACHA20_NONCEBYTES: number;
						public static XSALSA20_NONCEBYTES: number;
						public static XSALSA20_MESSAGEBYTES_MAX: number;
						public static MESSAGEBYTES_MAX: number;
						public static NONCEBYTES: number;
						public static KEYBYTES: number;
						public static CHACHA20_IETF_KEYBYTES: number;
						public static CHACHA20_KEYBYTES: number;
						public static SALSA20_KEYBYTES: number;
					}
					export module Stream {
						export class Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Stream.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Stream$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoStreamKeygen(param0: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): com.goterl.lazycode.lazysodium.utils.Key;
								cryptoStream(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): native.Array<number>;
								cryptoStreamXor(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key, param3: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
								cryptoStreamXorDecrypt(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key, param3: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
								cryptoStreamXorIc(param0: string, param1: native.Array<number>, param2: number, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
								cryptoStreamXorIcDecrypt(param0: string, param1: native.Array<number>, param2: number, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
							});
							public constructor();
							public cryptoStreamXor(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key, param3: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
							public cryptoStreamXorDecrypt(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key, param3: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
							public cryptoStreamXorIc(param0: string, param1: native.Array<number>, param2: number, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
							public cryptoStreamKeygen(param0: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): com.goterl.lazycode.lazysodium.utils.Key;
							public cryptoStreamXorIcDecrypt(param0: string, param1: native.Array<number>, param2: number, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
							public cryptoStream(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): native.Array<number>;
						}
						export class Method {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Stream.Method>;
							public static CHACHA20: com.goterl.lazycode.lazysodium.interfaces.Stream.Method;
							public static CHACHA20_IETF: com.goterl.lazycode.lazysodium.interfaces.Stream.Method;
							public static SALSA20: com.goterl.lazycode.lazysodium.interfaces.Stream.Method;
							public static XSALSA20: com.goterl.lazycode.lazysodium.interfaces.Stream.Method;
							public static values(): native.Array<com.goterl.lazycode.lazysodium.interfaces.Stream.Method>;
							public static valueOf(param0: string): com.goterl.lazycode.lazysodium.interfaces.Stream.Method;
						}
						export class Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.Stream.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.Stream$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoStreamChaCha20Keygen(param0: native.Array<number>): void;
								cryptoStreamChaCha20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
								cryptoStreamChaCha20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
								cryptoStreamChacha20XorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
								cryptoStreamChaCha20IetfKeygen(param0: native.Array<number>): void;
								cryptoStreamChaCha20Ietf(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
								cryptoStreamChaCha20IetfXor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
								cryptoStreamChacha20IetfXorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
								cryptoStreamSalsa20Keygen(param0: native.Array<number>): void;
								cryptoStreamSalsa20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
								cryptoStreamSalsa20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
								cryptoStreamSalsa20XorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
								cryptoStreamXSalsa20Keygen(param0: native.Array<number>): void;
								cryptoStreamXSalsa20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
								cryptoStreamXSalsa20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							});
							public constructor();
							public cryptoStreamChaCha20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							public cryptoStreamSalsa20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							public cryptoStreamChaCha20Keygen(param0: native.Array<number>): void;
							public cryptoStreamXSalsa20Keygen(param0: native.Array<number>): void;
							public cryptoStreamXSalsa20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							public cryptoStreamChaCha20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
							public cryptoStreamSalsa20XorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
							public cryptoStreamSalsa20Keygen(param0: native.Array<number>): void;
							public cryptoStreamXSalsa20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
							public cryptoStreamChacha20XorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
							public cryptoStreamChaCha20IetfXor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							public cryptoStreamChaCha20Ietf(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
							public cryptoStreamChacha20IetfXorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
							public cryptoStreamChaCha20IetfKeygen(param0: native.Array<number>): void;
							public cryptoStreamSalsa20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module interfaces {
					export class StreamJava extends com.goterl.lazycode.lazysodium.interfaces.Stream {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.StreamJava>;
						/**
						 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.StreamJava interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
						 */
						public constructor(implementation: {
						});
						public constructor();
						public static CHACHA20_IETF_MESSAGEBYTES_MAX: number;
						public static SALSA20_NONCEBYTES: number;
						public static XCHACHA20_KEYBYTES: number;
						public static SALSA20_MESSAGEBYTES_MAX: number;
						public static SALSA2012_KEYBYTES: number;
						public static CHACHA20_MESSAGEBYTES_MAX: number;
						public static CHACHA20_IETF_NONCEBYTES: number;
						public static XSALSA20_KEYBYTES: number;
						public static CHACHA20_NONCEBYTES: number;
						public static XSALSA20_NONCEBYTES: number;
						public static XCHACHA20_NONCEBYTES: number;
						public static XSALSA20_MESSAGEBYTES_MAX: number;
						public static MESSAGEBYTES_MAX: number;
						public static XCHACHA20_MESSAGEBYTES_MAX: number;
						public static SALSA2012_MESSAGEBYTES_MAX: number;
						public static SALSA208_KEYBYTES: number;
						public static NONCEBYTES: number;
						public static KEYBYTES: number;
						public static CHACHA20_IETF_KEYBYTES: number;
						public static SALSA208_MESSAGEBYTES_MAX: number;
						public static SALSA2012_NONCEBYTES: number;
						public static CHACHA20_KEYBYTES: number;
						public static SALSA20_KEYBYTES: number;
						public static SALSA208_NONCEBYTES: number;
					}
					export module StreamJava {
						export class Lazy extends com.goterl.lazycode.lazysodium.interfaces.Stream.Lazy {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.StreamJava.Lazy>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.StreamJava$Lazy interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoStreamKeygen(param0: com.goterl.lazycode.lazysodium.interfaces.StreamJava.Method): com.goterl.lazycode.lazysodium.utils.Key;
								cryptoStream(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: com.goterl.lazycode.lazysodium.interfaces.StreamJava.Method): native.Array<number>;
								cryptoStreamXor(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key, param3: com.goterl.lazycode.lazysodium.interfaces.StreamJava.Method): string;
								cryptoStreamXorDecrypt(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key, param3: com.goterl.lazycode.lazysodium.interfaces.StreamJava.Method): string;
								cryptoStreamXorIc(param0: string, param1: native.Array<number>, param2: number, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.StreamJava.Method): string;
								cryptoStreamXorIcDecrypt(param0: string, param1: native.Array<number>, param2: number, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.StreamJava.Method): string;
								cryptoStreamKeygen(param0: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): com.goterl.lazycode.lazysodium.utils.Key;
								cryptoStream(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): native.Array<number>;
								cryptoStreamXor(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key, param3: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
								cryptoStreamXorDecrypt(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key, param3: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
								cryptoStreamXorIc(param0: string, param1: native.Array<number>, param2: number, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
								cryptoStreamXorIcDecrypt(param0: string, param1: native.Array<number>, param2: number, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
							});
							public constructor();
							public cryptoStreamXor(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key, param3: com.goterl.lazycode.lazysodium.interfaces.StreamJava.Method): string;
							public cryptoStreamXor(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key, param3: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
							public cryptoStreamXorIc(param0: string, param1: native.Array<number>, param2: number, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.StreamJava.Method): string;
							public cryptoStreamKeygen(param0: com.goterl.lazycode.lazysodium.interfaces.StreamJava.Method): com.goterl.lazycode.lazysodium.utils.Key;
							public cryptoStreamXorDecrypt(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key, param3: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
							public cryptoStreamXorIc(param0: string, param1: native.Array<number>, param2: number, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
							public cryptoStream(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: com.goterl.lazycode.lazysodium.interfaces.StreamJava.Method): native.Array<number>;
							public cryptoStreamXorIcDecrypt(param0: string, param1: native.Array<number>, param2: number, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.StreamJava.Method): string;
							public cryptoStreamKeygen(param0: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): com.goterl.lazycode.lazysodium.utils.Key;
							public cryptoStreamXorIcDecrypt(param0: string, param1: native.Array<number>, param2: number, param3: com.goterl.lazycode.lazysodium.utils.Key, param4: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): string;
							public cryptoStreamXorDecrypt(param0: string, param1: native.Array<number>, param2: com.goterl.lazycode.lazysodium.utils.Key, param3: com.goterl.lazycode.lazysodium.interfaces.StreamJava.Method): string;
							public cryptoStream(param0: native.Array<number>, param1: com.goterl.lazycode.lazysodium.utils.Key, param2: com.goterl.lazycode.lazysodium.interfaces.Stream.Method): native.Array<number>;
						}
						export class Method {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.StreamJava.Method>;
							public static SALSA20_12: com.goterl.lazycode.lazysodium.interfaces.StreamJava.Method;
							public static SALSA20_8: com.goterl.lazycode.lazysodium.interfaces.StreamJava.Method;
							public static XCHACHA20: com.goterl.lazycode.lazysodium.interfaces.StreamJava.Method;
							public static values(): native.Array<com.goterl.lazycode.lazysodium.interfaces.StreamJava.Method>;
							public static valueOf(param0: string): com.goterl.lazycode.lazysodium.interfaces.StreamJava.Method;
						}
						export class Native extends com.goterl.lazycode.lazysodium.interfaces.Stream.Native {
							public static class: java.lang.Class<com.goterl.lazycode.lazysodium.interfaces.StreamJava.Native>;
							/**
							 * Constructs a new instance of the com.goterl.lazycode.lazysodium.interfaces.StreamJava$Native interface with the provided implementation. An empty constructor exists calling super() when extending the interface class.
							 */
							public constructor(implementation: {
								cryptoStreamSalsa2012Keygen(param0: native.Array<number>): void;
								cryptoStreamSalsa2012(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
								cryptoStreamSalsa2012Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
								cryptoStreamSalsa208Keygen(param0: native.Array<number>): void;
								cryptoStreamSalsa208(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
								cryptoStreamSalsa208Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
								cryptoStreamXChaCha20Keygen(param0: native.Array<number>): void;
								cryptoStreamXChaCha20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
								cryptoStreamXChaCha20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
								cryptoStreamXChaCha20Ic(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
								cryptoStreamChaCha20Keygen(param0: native.Array<number>): void;
								cryptoStreamChaCha20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
								cryptoStreamChaCha20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
								cryptoStreamChacha20XorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
								cryptoStreamChaCha20IetfKeygen(param0: native.Array<number>): void;
								cryptoStreamChaCha20Ietf(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
								cryptoStreamChaCha20IetfXor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
								cryptoStreamChacha20IetfXorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
								cryptoStreamSalsa20Keygen(param0: native.Array<number>): void;
								cryptoStreamSalsa20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
								cryptoStreamSalsa20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
								cryptoStreamSalsa20XorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
								cryptoStreamXSalsa20Keygen(param0: native.Array<number>): void;
								cryptoStreamXSalsa20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
								cryptoStreamXSalsa20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							});
							public constructor();
							public cryptoStreamSalsa208Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							public cryptoStreamXSalsa20Keygen(param0: native.Array<number>): void;
							public cryptoStreamXChaCha20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							public cryptoStreamSalsa2012Keygen(param0: native.Array<number>): void;
							public cryptoStreamChaCha20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
							public cryptoStreamSalsa208(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
							public cryptoStreamSalsa20Keygen(param0: native.Array<number>): void;
							public cryptoStreamXChaCha20Ic(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
							public cryptoStreamChacha20XorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
							public cryptoStreamChaCha20IetfXor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							public cryptoStreamChaCha20Ietf(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
							public cryptoStreamChacha20IetfXorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
							public cryptoStreamChaCha20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							public cryptoStreamSalsa20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							public cryptoStreamChaCha20Keygen(param0: native.Array<number>): void;
							public cryptoStreamSalsa208Keygen(param0: native.Array<number>): void;
							public cryptoStreamXChaCha20Keygen(param0: native.Array<number>): void;
							public cryptoStreamSalsa2012(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
							public cryptoStreamXSalsa20Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							public cryptoStreamSalsa20XorIc(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: number, param5: native.Array<number>): boolean;
							public cryptoStreamXSalsa20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
							public cryptoStreamSalsa2012Xor(param0: native.Array<number>, param1: native.Array<number>, param2: number, param3: native.Array<number>, param4: native.Array<number>): boolean;
							public cryptoStreamXChaCha20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
							public cryptoStreamChaCha20IetfKeygen(param0: native.Array<number>): void;
							public cryptoStreamSalsa20(param0: native.Array<number>, param1: number, param2: native.Array<number>, param3: native.Array<number>): boolean;
						}
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module utils {
					export class BaseChecker {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.utils.BaseChecker>;
						public static isBetween(param0: com.sun.jna.NativeLong, param1: com.sun.jna.NativeLong, param2: com.sun.jna.NativeLong): boolean;
						public static isBetween(param0: number, param1: number, param2: number): boolean;
						public constructor();
						public static correctLen(param0: number, param1: number): boolean;
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module utils {
					export class Constants {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.utils.Constants>;
						public static UNSIGNED_INT: number;
						public static SIZE_MAX: number;
						public static GB_256: number;
						public constructor();
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module utils {
					export class Detached {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.utils.Detached>;
						public constructor(param0: native.Array<number>);
						public getMac(): native.Array<number>;
						public getMacString(): string;
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module utils {
					export class DetachedDecrypt extends com.goterl.lazycode.lazysodium.utils.Detached {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.utils.DetachedDecrypt>;
						public getMessageString(): string;
						public getMessage(): native.Array<number>;
						public constructor(param0: native.Array<number>);
						public constructor(param0: native.Array<number>, param1: native.Array<number>);
						public constructor(param0: native.Array<number>, param1: native.Array<number>, param2: java.nio.charset.Charset);
						public getMessageString(param0: java.nio.charset.Charset): string;
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module utils {
					export class DetachedEncrypt extends com.goterl.lazycode.lazysodium.utils.Detached {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.utils.DetachedEncrypt>;
						public getCipherString(): string;
						public constructor(param0: native.Array<number>);
						public constructor(param0: native.Array<number>, param1: native.Array<number>);
						public getCipher(): native.Array<number>;
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module utils {
					export class Key {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.utils.Key>;
						public getAsBytes(): native.Array<number>;
						public static generate(param0: com.goterl.lazycode.lazysodium.LazySodium, param1: number): com.goterl.lazycode.lazysodium.utils.Key;
						public static fromPlainString(param0: string): com.goterl.lazycode.lazysodium.utils.Key;
						public getAsPlainString(): string;
						public static fromHexString(param0: string): com.goterl.lazycode.lazysodium.utils.Key;
						public getAsPlainString(param0: java.nio.charset.Charset): string;
						public equals(param0: any): boolean;
						public getAsHexString(): string;
						public static fromPlainString(param0: string, param1: java.nio.charset.Charset): com.goterl.lazycode.lazysodium.utils.Key;
						public static fromBytes(param0: native.Array<number>): com.goterl.lazycode.lazysodium.utils.Key;
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module utils {
					export class KeyPair {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.utils.KeyPair>;
						public constructor(param0: com.goterl.lazycode.lazysodium.utils.Key, param1: com.goterl.lazycode.lazysodium.utils.Key);
						public getPublicKey(): com.goterl.lazycode.lazysodium.utils.Key;
						public equals(param0: any): boolean;
						public getSecretKey(): com.goterl.lazycode.lazysodium.utils.Key;
					}
				}
			}
		}
	}
}

declare module com {
	export module goterl {
		export module lazycode {
			export module lazysodium {
				export module utils {
					export class SessionPair {
						public static class: java.lang.Class<com.goterl.lazycode.lazysodium.utils.SessionPair>;
						public constructor(param0: native.Array<number>, param1: native.Array<number>);
						public getTx(): native.Array<number>;
						public getTxString(): string;
						public getRx(): native.Array<number>;
						public constructor(param0: string, param1: string);
						public getRxString(): string;
					}
				}
			}
		}
	}
}

//Generics information:

