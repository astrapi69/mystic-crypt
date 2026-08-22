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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import javax.crypto.Cipher;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.api.algorithm.AesAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.Algorithm;
import io.github.astrapi69.crypt.data.model.CryptModel;

/**
 * The unit test class for the class {@link HexableEncryptor} and {@link HexableDecryptor}
 */
public class HexableDecryptorTest
{

	CryptModel<Cipher, String, String> cryptModel;
	String firstKey;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeEach
	protected void setUp()
	{
		firstKey = "1234567890123456";
		cryptModel = CryptModel.<Cipher, String, String> builder().key(firstKey)
			.algorithm(AesAlgorithm.AES).build();
	}

	/**
	 * Test chained encrypt and decrypt with {@link HexableEncryptor#encrypt(String)} and
	 * {@link HexableDecryptor#decrypt(String)}.
	 *
	 * @throws Exception
	 *             is thrown if any security exception occured.
	 */
	@Test
	public void testEncryptDecrypt() throws Exception
	{
		String test;
		String key;
		HexableEncryptor encryptor;
		String encrypted;
		HexableDecryptor decryptor;
		String decryted;

		test = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";
		key = "1234567890123456";
		encryptor = new HexableEncryptor(key);
		encrypted = encryptor.encrypt(test);

		decryptor = new HexableDecryptor(key);
		decryted = decryptor.decrypt(encrypted);
		assertTrue(test.equals(decryted),
			"String before encryption is not equal after decryption.");
	}

	/**
	 * Test chained encrypt and decrypt with {@link HexableEncryptor#encrypt(String)} and
	 * {@link HexableDecryptor#decrypt(String)}.
	 *
	 * @throws Exception
	 *             is thrown if any security exception occured.
	 */
	@Test
	public void testEncryptDecryptWithModel() throws Exception
	{
		String test;
		HexableEncryptor encryptor;
		String encrypted;
		HexableDecryptor decryptor;
		String decryted;

		test = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";

		encryptor = new HexableEncryptor(cryptModel);
		encrypted = encryptor.encrypt(test);

		cryptModel.setOperationMode(Cipher.DECRYPT_MODE);
		decryptor = new HexableDecryptor(cryptModel);
		decryted = decryptor.decrypt(encrypted);
		assertTrue(test.equals(decryted),
			"String before encryption is not equal after decryption.");
	}

	/**
	 * Test method for {@link HexableDecryptor#decrypt(String)}, encrypted data that is shorter than
	 * the nonce has to be rejected
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void testDecryptWithDataShorterThanTheNonce() throws Exception
	{
		HexableDecryptor decryptor = new HexableDecryptor("1234567890123456");

		assertThrows(IllegalArgumentException.class, () -> decryptor.decrypt("00112233"));
	}

	/**
	 * Test method for {@link HexableDecryptor#decrypt(String)}, data of exactly the nonce length
	 * (12 bytes = 24 hex characters) is <em>not</em> rejected by the length guard (it fails later
	 * during GCM decryption). This pins the boundary of the {@code length < NONCE_LENGTH} check so
	 * a {@code <=} mutant is caught.
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void testDecryptWithDataOfExactlyTheNonceLengthIsNotRejectedByTheLengthGuard()
		throws Exception
	{
		HexableDecryptor decryptor = new HexableDecryptor("1234567890123456");

		// 12 bytes worth of hex - exactly the nonce length, leaving an empty ciphertext
		Exception exception = assertThrows(Exception.class,
			() -> decryptor.decrypt("000000000000000000000000"));
		assertFalse(exception instanceof IllegalArgumentException,
			"data of exactly the nonce length must pass the length guard, not be rejected by it");
	}

	/**
	 * Test method for {@link HexableDecryptor#HexableDecryptor(String, Algorithm)}, the algorithm
	 * is mandatory
	 */
	@Test
	public void testConstructorWithoutAlgorithm()
	{
		assertThrows(IllegalArgumentException.class,
			() -> new HexableDecryptor("1234567890123456", null));
	}
}
