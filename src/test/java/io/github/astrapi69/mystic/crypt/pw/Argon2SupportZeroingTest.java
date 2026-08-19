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

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit test class confirming {@link Argon2Support} zeroes its password argument after use.
 */
public class Argon2SupportZeroingTest
{

	private static final String PASSWORD = "correct horse battery staple";

	/**
	 * Test method for {@link Argon2Support#hash(char[])} confirming the password array is zeroed
	 * after use
	 */
	@Test
	public void testHashZeroesPasswordArray()
	{
		final char[] password = PASSWORD.toCharArray();

		Argon2Support.hash(password);

		for (final char c : password)
		{
			assertTrue(c == '\0');
		}
	}

	/**
	 * Test method for {@link Argon2Support#verify(char[], String)} confirming the password array is
	 * zeroed after use
	 */
	@Test
	public void testVerifyZeroesPasswordArray()
	{
		final String encoded = Argon2Support.hash(PASSWORD.toCharArray());
		final char[] password = PASSWORD.toCharArray();

		Argon2Support.verify(password, encoded);

		for (final char c : password)
		{
			assertTrue(c == '\0');
		}
	}

}
