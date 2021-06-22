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
package io.github.astrapi69.crypto.pw;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

import java.nio.charset.StandardCharsets;

import org.testng.annotations.Test;

import io.github.astrapi69.collections.array.ArrayFactory;

/**
 * The unit test class for the class {@link PasswordByteEncryptor}
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class PasswordByteEncryptorTest
{

	/**
	 * Test method for test the method {@link PasswordByteEncryptor#encrypt(byte[])}
	 */
	@Test
	public void testEncrypt() throws Exception
	{
		// declare variables
		byte[] actual;
		byte[] expected;
		String password;
		String text;
		byte[] textBytes;
		byte[] encryptedBytes;
		PasswordByteEncryptor encryptor;
		// new scenario
		// init variables for current scenario
		password = "foo";
		text = "bar";
		textBytes = text.getBytes(StandardCharsets.UTF_8);
		encryptor = new PasswordByteEncryptor(password);
		// test method with current variables
		encryptedBytes = encryptor.encrypt(textBytes);
		assertNotNull(encryptedBytes);
		actual = encryptedBytes;
		expected = ArrayFactory.newByteArray(-118, -125, -30, 16, 87, 88, -110, -94);
		assertEquals(actual, expected);
	}

}
