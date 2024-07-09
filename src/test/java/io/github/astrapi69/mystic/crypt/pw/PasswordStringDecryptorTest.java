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
package io.github.astrapi69.mystic.crypt.pw;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;

/**
 * The unit test class for the class {@link PasswordStringDecryptor}
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class PasswordStringDecryptorTest
{

	/**
	 * Test method for test the method {@link PasswordStringDecryptor#decrypt(String)}
	 */
	@Test
	public void testDecrypt() throws Exception
	{
		// declare variables
		String actual;
		String expected;
		String password;
		String text;
		String encryptedMessage;
		String decryptedMessage;
		PasswordStringEncryptor encryptor;
		PasswordStringDecryptor decryptor;
		// new scenario
		// init variables for current scenario
		password = "foo";
		text = "bar";
		encryptor = new PasswordStringEncryptor(password);
		decryptor = new PasswordStringDecryptor(password);
		// prepare encrypted message with current variables
		encryptedMessage = encryptor.encrypt(text);
		assertNotNull(encryptedMessage);
		actual = encryptedMessage;
		expected = "ioPiEFdYkqI=";
		assertEquals(actual, expected);
		// test method with current encrypted message
		decryptedMessage = decryptor.decrypt(encryptedMessage);
		assertNotNull(decryptedMessage);
		actual = decryptedMessage;
		expected = text;
		assertEquals(actual, expected);
	}
}
