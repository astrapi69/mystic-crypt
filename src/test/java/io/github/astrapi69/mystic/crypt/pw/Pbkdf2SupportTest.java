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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * The unit test class for the class {@link Pbkdf2Support}
 */
public class Pbkdf2SupportTest
{

	/**
	 * Test method for {@link Pbkdf2Support#hash(char[])} and
	 * {@link Pbkdf2Support#verify(char[], String)}
	 */
	@Test
	public void testHashAndVerify()
	{
		final char[] password = "correct horse battery staple".toCharArray();
		final String encoded = Pbkdf2Support.hash(password);

		assertTrue(Pbkdf2Support.verify(password, encoded));
	}

	/**
	 * Test method for {@link Pbkdf2Support#verify(char[], String)} with the wrong password
	 */
	@Test
	public void testVerifyFailsForWrongPassword()
	{
		final String encoded = Pbkdf2Support.hash("correct horse battery staple".toCharArray());

		assertFalse(Pbkdf2Support.verify("wrong password".toCharArray(), encoded));
	}

	/**
	 * Test method for {@link Pbkdf2Support#hash(char[])} confirming two hashes of the same password
	 * differ (random salt per call)
	 */
	@Test
	public void testHashIsNonDeterministic()
	{
		final char[] password = "correct horse battery staple".toCharArray();
		final String first = Pbkdf2Support.hash(password);
		final String second = Pbkdf2Support.hash(password);

		assertNotEquals(first, second);
		assertTrue(Pbkdf2Support.verify(password, first));
		assertTrue(Pbkdf2Support.verify(password, second));
	}

	/**
	 * Test method for {@link Pbkdf2Support#verify(char[], String)} with a tampered encoded hash
	 */
	@Test
	public void testVerifyFailsForTamperedHash()
	{
		final char[] password = "correct horse battery staple".toCharArray();
		final String encoded = Pbkdf2Support.hash(password);
		final String tampered = encoded.substring(0, encoded.length() - 1)
			+ (encoded.charAt(encoded.length() - 1) == 'A' ? 'B' : 'A');

		assertFalse(Pbkdf2Support.verify(password, tampered));
	}

	/**
	 * Test method for {@link Pbkdf2Support#verify(char[], String)} with a malformed encoded string
	 */
	@Test
	public void testVerifyFailsForMalformedEncoded()
	{
		assertFalse(Pbkdf2Support.verify("password".toCharArray(), "not-a-valid-hash"));
	}

}
