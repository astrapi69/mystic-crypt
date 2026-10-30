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
package io.github.astrapi69.mystic.crypt.secret;

import java.security.SecureRandom;

/**
 * The random values a cryptographic operation needs - salts, nonces, IVs, generated passwords -
 * drawn from {@link SecureRandom} directly.
 * <p>
 * Not through randomizer: that library generates test data, and before its 10.5 its default
 * generator was seeded with the current time in milliseconds, which made every salt, nonce and
 * password this library drew through it predictable (GHSA-rmpr-hqmh-r8gp, #241). One
 * {@link SecureRandom} with the platform's default algorithm serves every caller; it seeds itself
 * from the operating system, never blocks waiting for entropy the way
 * {@link SecureRandom#getInstanceStrong()} can on Linux, and is safe to share between threads.
 */
public final class SecretRandom
{

	private static final SecureRandom SOURCE = new SecureRandom();

	private static final String ALPHANUMERIC = "abcdefghijklmnopqrstuvwxyz"
		+ "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

	private SecretRandom()
	{
	}

	/**
	 * Draws random bytes, for a salt, a nonce or an IV
	 *
	 * @param length
	 *            how many bytes
	 * @return the bytes
	 */
	public static byte[] bytes(final int length)
	{
		byte[] bytes = new byte[length];
		SOURCE.nextBytes(bytes);
		return bytes;
	}

	/**
	 * Draws a random string of lowercase and uppercase letters and digits, each of the 62
	 * characters with the same probability: the alphabet randomizer's generated passwords used,
	 * drawn from a source fit for them
	 *
	 * @param length
	 *            how many characters
	 * @return the string
	 */
	public static String alphanumeric(final int length)
	{
		StringBuilder drawn = new StringBuilder(length);
		for (int i = 0; i < length; i++)
		{
			drawn.append(ALPHANUMERIC.charAt(SOURCE.nextInt(ALPHANUMERIC.length())));
		}
		return drawn.toString();
	}
}
