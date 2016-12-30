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

import org.apache.log4j.Logger;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

/**
 * Test class for the class {@link HexEncryptor} and {@link HexDecryptor}.
 */
public class HexEncryptDecryptorTest
{

	/** The Constant logger. */
	private static final Logger logger = Logger.getLogger(HexEncryptDecryptorTest.class.getName());

	/**
	 * Test chained encrypt and decrypt with {@link HexEncryptor#encrypt(String)} and
	 * {@link HexDecryptor#decrypt(String)}.
	 *
	 * @throws Exception
	 *             is thrown if any security exception occured.
	 */
	@Test
	public void testEncryptDecrypt() throws Exception
	{
		final String test = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";
		final String key = "1234567890123456";
		final HexEncryptor encryptor = new HexEncryptor(key);
		final String encrypted = encryptor.encrypt(test);
		logger.debug("String after encryption:" + encrypted);

		final HexDecryptor decryptor = new HexDecryptor(key);
		final String decryted = decryptor.decrypt(encrypted);
		logger.debug("String after decryption:" + decryted);
		AssertJUnit.assertTrue("String before encryption is not equal after decryption.",
			test.equals(decryted));
	}

}
