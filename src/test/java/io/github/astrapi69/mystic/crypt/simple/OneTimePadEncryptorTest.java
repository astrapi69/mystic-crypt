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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.collection.array.ArrayFactory;

/**
 * The unit test class for the class {@link OneTimePadEncryptor}
 */
public class OneTimePadEncryptorTest
{

	/**
	 * Test method for the {@link OneTimePadEncryptor#encrypt(byte[])} method
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public void testEncrypt() throws Exception
	{
		byte[] actual;
		byte[] expected;
		OneTimePadEncryptor encryptor;
		String plainMessage;
		String theKey;
		byte[] key;
		plainMessage = "RandomStringFactory.newRandomLongString(10)";
		byte[] plainMessageBytes = plainMessage.getBytes(StandardCharsets.UTF_8);
		theKey = "topsecret";
		key = theKey.getBytes(StandardCharsets.UTF_8);
		encryptor = new OneTimePadEncryptor(key);

		actual = encryptor.encrypt(plainMessageBytes);
		expected = ArrayFactory.newByteArray(38, 14, 30, 23, 10, 14, 33, 17, 6, 26, 29, 20, 53, 18,
			16, 7, 28, 1, 10, 93, 29, 22, 4, 33, 18, 29, 23, 28, 30, 63, 28, 29, 20, 32, 7, 1, 26,
			29, 20, 91, 66, 67, 90);
		assertArrayEquals(actual, expected);
	}
}
