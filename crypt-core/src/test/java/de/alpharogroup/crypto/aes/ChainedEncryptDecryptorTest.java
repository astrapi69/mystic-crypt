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
package de.alpharogroup.crypto.aes;

import org.testng.AssertJUnit;
import org.testng.annotations.Test;

/**
 * Test class for the class {@link ChainedEncryptor} and {@link ChainedDecryptor}.
 */
public class ChainedEncryptDecryptorTest
{

	/**
	 * Test chained encrypt and decrypt with {@link ChainedEncryptor#encrypt(String)} and
	 * {@link ChainedDecryptor#decrypt(String)}.
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
		final HexEncryptor firstEncryptor = new HexEncryptor(firstKey);
		final HexEncryptor secondEncryptor = new HexEncryptor(secondKey);
		final HexEncryptor thirdEncryptor = new HexEncryptor(thirdKey);
		final ChainedEncryptor encryptor = new ChainedEncryptor(firstEncryptor, secondEncryptor,
			thirdEncryptor);

		final String encrypted = encryptor.encrypt(secretMessage);
		final HexDecryptor firstDecryptor = new HexDecryptor(firstKey);
		final HexDecryptor secondDecryptor = new HexDecryptor(secondKey);
		final HexDecryptor thirdDecryptor = new HexDecryptor(thirdKey);
		final ChainedDecryptor decryptor = new ChainedDecryptor(thirdDecryptor, secondDecryptor,
			firstDecryptor);

		final String decryted = decryptor.decrypt(encrypted);
		AssertJUnit.assertTrue("String before encryption is not equal after decryption.",
			secretMessage.equals(decryted));
	}
}
