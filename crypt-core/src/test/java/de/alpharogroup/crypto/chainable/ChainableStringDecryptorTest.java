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
package de.alpharogroup.crypto.chainable;

import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.hex.HexableDecryptor;
import de.alpharogroup.crypto.hex.HexableEncryptor;

/**
 * Test class for the class {@link ChainableStringEncryptor} and {@link ChainableStringDecryptor}.
 */
public class ChainableStringDecryptorTest
{

	/**
	 * Test chained encrypt and decrypt with {@link ChainableStringEncryptor#encrypt(String)} and
	 * {@link ChainableStringDecryptor#decrypt(String)}.
	 *
	 * @throws Exception
	 *             is thrown if any security exception occured.
	 */
	@Test
	public void testChainedEncryptDecrypt() throws Exception
	{
		final String secretMessage = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";
		final String firstKey = "D1D15ED36B887AF1";
		final String secondKey = "44850AD044361AE8";
		final String thirdKey = "BD0F34C849772DC6";
		final HexableEncryptor firstEncryptor = new HexableEncryptor(firstKey);
		final HexableEncryptor secondEncryptor = new HexableEncryptor(secondKey);
		final HexableEncryptor thirdEncryptor = new HexableEncryptor(thirdKey);
		final ChainableStringEncryptor encryptor = new ChainableStringEncryptor(firstEncryptor, secondEncryptor,
			thirdEncryptor);

		final String encrypted = encryptor.encrypt(secretMessage);
		final HexableDecryptor firstDecryptor = new HexableDecryptor(firstKey);
		final HexableDecryptor secondDecryptor = new HexableDecryptor(secondKey);
		final HexableDecryptor thirdDecryptor = new HexableDecryptor(thirdKey);
		final ChainableStringDecryptor decryptor = new ChainableStringDecryptor(thirdDecryptor, secondDecryptor,
			firstDecryptor);

		final String decryted = decryptor.decrypt(encrypted);
		AssertJUnit.assertTrue("String before encryption is not equal after decryption.",
			secretMessage.equals(decryted));
	}

}
