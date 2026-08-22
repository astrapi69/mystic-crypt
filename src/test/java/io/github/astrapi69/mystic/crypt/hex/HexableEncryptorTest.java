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
package io.github.astrapi69.mystic.crypt.hex;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import javax.crypto.Cipher;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.collection.list.ListFactory;
import io.github.astrapi69.crypt.api.algorithm.AesAlgorithm;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.crypt.data.model.CryptObjectDecorator;
import io.github.astrapi69.mystic.crypt.algorithm.MysticSymmetricAlgorithm;

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

	/**
	 * Test method for {@link HexableEncryptor#encrypt(byte[])}, a hexable encryptor works on
	 * strings only
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void testEncryptByteArrayIsNotSupported() throws Exception
	{
		HexableEncryptor encryptor = new HexableEncryptor("1234567890123456");

		assertThrows(UnsupportedOperationException.class,
			() -> encryptor.encrypt(new byte[] { 1, 2, 3 }));
	}

	/**
	 * Test method for {@link HexableEncryptor#encrypt(String)} with the transformation
	 * ChaCha20-Poly1305, every encryption uses a fresh nonce and can be decrypted again
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void testEncryptDecryptWithChaCha20Poly1305() throws Exception
	{
		String key = "12345678901234567890123456789012";
		HexableEncryptor encryptor = new HexableEncryptor(key,
			MysticSymmetricAlgorithm.CHACHA20_POLY1305);
		HexableDecryptor decryptor = new HexableDecryptor(key,
			MysticSymmetricAlgorithm.CHACHA20_POLY1305);
		String plaintext = "the quick brown fox jumps over the lazy dog";

		String first = encryptor.encrypt(plaintext);
		String second = encryptor.encrypt(plaintext);

		assertNotEquals(first, second);
		assertEquals(plaintext, decryptor.decrypt(first));
		assertEquals(plaintext, decryptor.decrypt(second));
	}

	/**
	 * Test method for {@link HexableEncryptor#encrypt(String)}, every configured decorator has to
	 * be applied on the plain text before it is encrypted
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void testEmptyDecoratorListIsTreatedLikeNoDecorators() throws Exception
	{
		String key = "1234567890123456";
		String plaintext = "Lorem ipsum";
		HexableEncryptor encryptor = new HexableEncryptor(
			CryptModel.<Cipher, String, String> builder().key(key)
				.decorators(ListFactory.newArrayList()).build());
		HexableDecryptor decryptor = new HexableDecryptor(
			CryptModel.<Cipher, String, String> builder().key(key)
				.decorators(ListFactory.newArrayList()).build());

		String encrypted = encryptor.encrypt(plaintext);

		assertEquals(plaintext, decryptor.decrypt(encrypted));
		assertEquals(plaintext, new HexableDecryptor(key).decrypt(encrypted));

		CryptModel<Cipher, String, String> nullDecorators = CryptModel
			.<Cipher, String, String> builder().key(key).build();
		nullDecorators.setDecorators(null);
		HexableEncryptor encryptorWithNull = new HexableEncryptor(nullDecorators);
		HexableDecryptor decryptorWithNull = new HexableDecryptor(nullDecorators);

		assertEquals(plaintext, decryptorWithNull.decrypt(encryptorWithNull.encrypt(plaintext)));
	}

	/**
	 * Test method for {@link HexableEncryptor#encrypt(String)}, every configured decorator has to
	 * be applied on the plain text before it is encrypted
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void testEncryptAppliesEveryDecoratorBeforeEncryption() throws Exception
	{
		String key = "1234567890123456";
		String plaintext = "Lorem ipsum";
		HexableEncryptor encryptor = new HexableEncryptor(CryptModel
			.<Cipher, String, String> builder().key(key)
			.decorators(ListFactory.newArrayList(
				CryptObjectDecorator.<String> builder().prefix("<<").suffix(">>").build(),
				CryptObjectDecorator.<String> builder().prefix("[").suffix("]").build()))
			.build());
		// a decryptor without decorators answers the decorated plain text
		HexableDecryptor decryptorWithoutDecorators = new HexableDecryptor(key);
		HexableDecryptor decryptorWithDecorators = new HexableDecryptor(CryptModel
			.<Cipher, String, String> builder().key(key)
			.decorators(ListFactory.newArrayList(
				CryptObjectDecorator.<String> builder().prefix("<<").suffix(">>").build(),
				CryptObjectDecorator.<String> builder().prefix("[").suffix("]").build()))
			.build());

		String encrypted = encryptor.encrypt(plaintext);

		assertEquals("[<<Lorem ipsum>>]", decryptorWithoutDecorators.decrypt(encrypted));
		assertEquals(plaintext, decryptorWithDecorators.decrypt(encrypted));
	}
}
