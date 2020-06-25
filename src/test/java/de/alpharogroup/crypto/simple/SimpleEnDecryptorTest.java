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
package de.alpharogroup.crypto.simple;

import static org.testng.AssertJUnit.assertTrue;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.testng.annotations.Test;

import de.alpharogroup.crypto.compound.CompoundAlgorithm;

/**
 * Test class for the {@link SimpleEncryptor} and {@link SimpleDecryptor}
 */
public class SimpleEnDecryptorTest {

	/**
	 * Test encrypt and decrypt with {@link SimpleEncryptor#encrypt(String)} and
	 * {@link SimpleDecryptor#decrypt(String)}
	 *
	 * @throws BadPaddingException                is thrown if
	 *                                            {@link Cipher#doFinal(byte[])}
	 *                                            fails.
	 * @throws IllegalBlockSizeException          is thrown if
	 *                                            {@link Cipher#doFinal(byte[])}
	 *                                            fails.
	 * @throws UnsupportedEncodingException       is thrown if the named charset is
	 *                                            not supported.
	 * @throws InvalidAlgorithmParameterException is thrown if initialization of the
	 *                                            cipher object fails.
	 * @throws NoSuchPaddingException             is thrown if instantiation of the
	 *                                            cipher object fails.
	 * @throws InvalidKeySpecException            is thrown if generation of the
	 *                                            SecretKey object fails.
	 * @throws NoSuchAlgorithmException           is thrown if instantiation of the
	 *                                            SecretKeyFactory object fails.
	 * @throws InvalidKeyException                is thrown if initialization of the
	 *                                            cipher object fails.
	 */
	@Test
	public void testEncrypt() throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException,
			BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException {
		String actual;
		String expected;
		SimpleEncryptor encryptor;
		String encrypted;
		SimpleDecryptor decryptor;

		expected = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";

		encryptor = new SimpleEncryptor(CompoundAlgorithm.PRIVATE_KEY);

		encrypted = encryptor.encrypt(expected);
		decryptor = new SimpleDecryptor(CompoundAlgorithm.PRIVATE_KEY);
		actual = decryptor.decrypt(encrypted);
		assertTrue("String before encryption is not equal after decryption.", expected.equals(actual));
	}

}
