/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto.hex;

import static org.testng.AssertJUnit.assertTrue;

import org.testng.annotations.Test;

/**
 * The unit test class for the class {@link HexableEncryptor} and {@link HexableDecryptor}
 */
public class HexableDecryptorTest
{

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
		assertTrue("String before encryption is not equal after decryption.",
			test.equals(decryted));
	}


}
