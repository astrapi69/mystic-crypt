/*
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package io.github.astrapi69.mystic.crypt.key;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.mystic.crypt.algorithm.MysticSymmetricAlgorithm;
import io.github.astrapi69.mystic.crypt.base.BaseByteArrayDecryptor;
import io.github.astrapi69.mystic.crypt.base.BaseByteArrayEncryptor;

/**
 * The unit test class for the class {@link X25519KeyExchange}
 */
public class X25519KeyExchangeTest
{

	/**
	 * Test method for
	 * {@link X25519KeyExchange#deriveSharedSecret(java.security.PrivateKey, java.security.PublicKey, int)}
	 *
	 * <p>
	 * Two independently generated key pairs must derive the identical shared secret when each party
	 * combines their own private key with the other party's public key.
	 */
	@Test
	public void testBothPartiesDeriveTheSameSharedSecret() throws Exception
	{
		KeyPair alice = X25519KeyExchange.newKeyPair();
		KeyPair bob = X25519KeyExchange.newKeyPair();

		SecretKey aliceView = X25519KeyExchange.deriveSharedSecret(alice.getPrivate(),
			bob.getPublic(), 32);
		SecretKey bobView = X25519KeyExchange.deriveSharedSecret(bob.getPrivate(),
			alice.getPublic(), 32);

		assertNotNull(aliceView);
		assertArrayEquals(aliceView.getEncoded(), bobView.getEncoded());
		assertEquals(32, aliceView.getEncoded().length);
	}

	/**
	 * End-to-end test: the shared secret derived via X25519 + HKDF is used directly as an AES key
	 * with {@link BaseByteArrayEncryptor}/{@link BaseByteArrayDecryptor} (which already supports
	 * AES/GCM with a fresh nonce per call).
	 */
	@Test
	public void testEndToEndEncryptionWithDerivedSharedSecret() throws Exception
	{
		KeyPair alice = X25519KeyExchange.newKeyPair();
		KeyPair bob = X25519KeyExchange.newKeyPair();

		SecretKey aliceKey = X25519KeyExchange.deriveSharedSecret(alice.getPrivate(),
			bob.getPublic(), 32);
		SecretKey bobKey = X25519KeyExchange.deriveSharedSecret(bob.getPrivate(), alice.getPublic(),
			32);

		CryptModel<Cipher, SecretKey, String> encryptModel = CryptModel
			.<Cipher, SecretKey, String> builder().key(aliceKey)
			.algorithm(MysticSymmetricAlgorithm.AES_GCM_NO_PADDING).build();
		CryptModel<Cipher, SecretKey, String> decryptModel = CryptModel
			.<Cipher, SecretKey, String> builder().key(bobKey)
			.algorithm(MysticSymmetricAlgorithm.AES_GCM_NO_PADDING).build();

		BaseByteArrayEncryptor encryptor = new BaseByteArrayEncryptor(encryptModel);
		BaseByteArrayDecryptor decryptor = new BaseByteArrayDecryptor(decryptModel);

		byte[] plaintext = "the quick brown fox jumps over the lazy dog"
			.getBytes(StandardCharsets.UTF_8);
		byte[] encrypted = encryptor.encrypt(plaintext);
		byte[] decrypted = decryptor.decrypt(encrypted);

		assertArrayEquals(plaintext, decrypted);
	}

}
