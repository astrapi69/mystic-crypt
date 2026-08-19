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
package io.github.astrapi69.mystic.crypt.simple;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.api.algorithm.compound.CompoundAlgorithm;

/**
 * Test class for the {@link SimpleEncryptor} and {@link SimpleDecryptor}
 */
public class SimpleEnDecryptorTest
{

	/**
	 * Test encrypt and decrypt with {@link SimpleEncryptor#encrypt(String)} and
	 * {@link SimpleDecryptor#decrypt(String)}
	 *
	 * @throws Exception
	 *             is thrown if any security error occurs
	 */
	@Test
	public void testEncrypt() throws Exception
	{
		String actual;
		String expected;
		SimpleEncryptor encryptor;
		String encrypted;
		SimpleDecryptor decryptor;

		expected = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";

		encryptor = new SimpleEncryptor(CompoundAlgorithm.PASSWORD);

		encrypted = encryptor.encrypt(expected);
		decryptor = new SimpleDecryptor(CompoundAlgorithm.PASSWORD);
		actual = decryptor.decrypt(encrypted);
		assertEquals(expected, actual, "String before encryption is not equal after decryption.");
	}

	/**
	 * Regression test proving the default PBE algorithm/salt is no longer deterministic: encrypting
	 * the same plaintext twice on the same {@link SimpleEncryptor} instance must produce different
	 * ciphertext each time (a fresh salt per call).
	 *
	 * @throws Exception
	 *             is thrown if any security error occurs
	 */
	@Test
	public void testEncryptTwiceProducesDifferentCiphertext() throws Exception
	{
		SimpleEncryptor encryptor = new SimpleEncryptor(CompoundAlgorithm.PASSWORD);
		String plaintext = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";

		String first = encryptor.encrypt(plaintext);
		String second = encryptor.encrypt(plaintext);

		assertNotEquals(first, second);
	}

}
