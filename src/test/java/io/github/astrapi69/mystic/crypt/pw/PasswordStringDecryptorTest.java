/*
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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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
	 *
	 * <p>
	 * A random salt is now generated per call, so the exact ciphertext is no longer deterministic;
	 * assert non-determinism across two calls plus successful round-trip decryption instead of a
	 * golden string literal.
	 */
	@Test
	public void testDecrypt() throws Exception
	{
		String password = "foo";
		String text = "bar";
		PasswordStringEncryptor encryptor = new PasswordStringEncryptor(password);
		PasswordStringDecryptor decryptor = new PasswordStringDecryptor(password);

		String firstEncrypted = encryptor.encrypt(text);
		String secondEncrypted = encryptor.encrypt(text);
		assertNotNull(firstEncrypted);
		assertNotNull(secondEncrypted);
		assertNotEquals(firstEncrypted, secondEncrypted);

		assertEquals(text, decryptor.decrypt(firstEncrypted));
		assertEquals(text, decryptor.decrypt(secondEncrypted));
	}
}
