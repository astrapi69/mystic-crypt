/**
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
package io.github.astrapi69.mystic.crypt.hex;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import javax.crypto.Cipher;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.api.algorithm.AesAlgorithm;
import io.github.astrapi69.crypt.data.model.CryptModel;

/**
 * The unit test class for the class {@link HexableEncryptor}
 */
public class HexableEncryptorTest
{

	/**
	 * Regression test proving the default AES transformation is no longer deterministic ECB:
	 * encrypting the same plaintext twice on the same {@link HexableEncryptor} instance must
	 * produce different ciphertext each time (a fresh GCM nonce per call).
	 */
	@Test
	public void testEncryptTwiceOnSameInstanceProducesDifferentCiphertext() throws Exception
	{
		HexableEncryptor encryptor = new HexableEncryptor("1234567890123456");
		String plaintext = "the quick brown fox jumps over the lazy dog";

		String first = encryptor.encrypt(plaintext);
		String second = encryptor.encrypt(plaintext);

		assertNotEquals(first, second);
	}

	/**
	 * The legacy, explicitly opted-in bare {@code AesAlgorithm.AES} (ECB) transformation must still
	 * round-trip correctly, since it remains the migration path for reading data encrypted before
	 * the GCM default was introduced.
	 */
	@Test
	public void testEncryptDecryptWithExplicitLegacyAlgorithm() throws Exception
	{
		String key = "1234567890123456";
		CryptModel<Cipher, String, String> model = CryptModel.<Cipher, String, String> builder()
			.key(key).algorithm(AesAlgorithm.AES).build();
		HexableEncryptor encryptor = new HexableEncryptor(model);
		HexableDecryptor decryptor = new HexableDecryptor(CryptModel
			.<Cipher, String, String> builder().key(key).algorithm(AesAlgorithm.AES).build());
		String plaintext = "Lorem ipsum dolor sit amet";

		String encrypted = encryptor.encrypt(plaintext);
		String decrypted = decryptor.decrypt(encrypted);

		assertEquals(plaintext, decrypted);
	}
}
