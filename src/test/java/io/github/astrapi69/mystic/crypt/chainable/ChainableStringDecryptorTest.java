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
package io.github.astrapi69.mystic.crypt.chainable;

import static org.testng.AssertJUnit.assertTrue;

import io.github.astrapi69.mystic.crypt.chainable.ChainableStringDecryptor;
import io.github.astrapi69.mystic.crypt.chainable.ChainableStringEncryptor;
import org.testng.annotations.Test;

import io.github.astrapi69.mystic.crypt.hex.HexableDecryptor;
import io.github.astrapi69.mystic.crypt.hex.HexableEncryptor;

/**
 * The unit test class for the class {@link ChainableStringEncryptor} and
 * {@link ChainableStringDecryptor}
 */
public class ChainableStringDecryptorTest
{

	/**
	 * Test chained encrypt and decrypt with {@link ChainableStringEncryptor#encrypt(String)} and
	 * {@link ChainableStringDecryptor#decrypt(String)}
	 *
	 * @throws Exception
	 *             is thrown if any security exception occured
	 */
	@Test
	public void testChainedEncryptDecrypt() throws Exception
	{
		String secretMessage;
		String firstKey;
		String secondKey;
		String thirdKey;
		HexableEncryptor firstEncryptor;
		HexableEncryptor secondEncryptor;
		HexableEncryptor thirdEncryptor;
		ChainableStringEncryptor encryptor;
		String encrypted;
		String decryted;
		HexableDecryptor firstDecryptor;
		HexableDecryptor secondDecryptor;
		HexableDecryptor thirdDecryptor;
		ChainableStringDecryptor decryptor;

		secretMessage = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";
		firstKey = "D1D15ED36B887AF1";
		secondKey = "44850AD044361AE8";
		thirdKey = "BD0F34C849772DC6";
		firstEncryptor = new HexableEncryptor(firstKey);
		secondEncryptor = new HexableEncryptor(secondKey);
		thirdEncryptor = new HexableEncryptor(thirdKey);
		encryptor = new ChainableStringEncryptor(firstEncryptor, secondEncryptor, thirdEncryptor);

		encrypted = encryptor.encrypt(secretMessage);
		firstDecryptor = new HexableDecryptor(firstKey);
		secondDecryptor = new HexableDecryptor(secondKey);
		thirdDecryptor = new HexableDecryptor(thirdKey);
		decryptor = new ChainableStringDecryptor(thirdDecryptor, secondDecryptor, firstDecryptor);

		decryted = decryptor.decrypt(encrypted);
		assertTrue("String before encryption is not equal after decryption.",
			secretMessage.equals(decryted));
	}

}
