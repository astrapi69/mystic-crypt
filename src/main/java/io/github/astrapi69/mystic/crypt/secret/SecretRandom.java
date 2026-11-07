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

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * The random values a cryptographic operation needs - salts, nonces, IVs, generated passwords,
 * certificate serial numbers - drawn from {@link SecureRandom} directly.
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

	/**
	 * The length of a certificate serial number: 159 bits fill the 20 octets RFC 5280 allows with
	 * the top bit of the first octet clear, so the DER encoding needs no sign byte
	 */
	private static final int SERIAL_NUMBER_BITS = 159;

	private SecretRandom()
	{
	}

	/**
	 * Draws a serial number for a new X.509 certificate as RFC 5280 section 4.1.2.2 asks for it: a
	 * positive integer of at most 20 octets in its DER encoding. It has 158 bits from
	 * {@link SecureRandom}, far above the 64 the CA/Browser Forum baseline requires, below a set
	 * 159th bit: so it is never 0, always 159 bits long, and its DER encoding always takes the 20
	 * octets, without a sign byte.
	 *
	 * @return the serial number
	 */
	public static BigInteger certificateSerialNumber()
	{
		return new BigInteger(SERIAL_NUMBER_BITS - 1, SOURCE).setBit(SERIAL_NUMBER_BITS - 1);
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

	/**
	 * Draws random characters from the given alphabet, for a generated password whose characters
	 * the caller chooses. Every distinct character of the alphabet is drawn with the same
	 * probability: {@link SecureRandom#nextInt(int)} rejects the part of its range that a modulo
	 * would favour, and a character that appears more than once in the alphabet counts once, so
	 * that a repetition does not weight the draw.
	 * <p>
	 * The result is a {@code char[]}, not a {@link String}, so that the caller can overwrite the
	 * secret once it is used.
	 *
	 * @param length
	 *            how many characters, 0 or more
	 * @param alphabet
	 *            the characters to draw from; not empty, and without surrogates, because a drawn
	 *            half of a surrogate pair is no character
	 * @return the drawn characters
	 * @throws NullPointerException
	 *             if the alphabet is null
	 * @throws IllegalArgumentException
	 *             if the length is negative, or the alphabet is empty or holds a surrogate
	 */
	public static char[] characters(final int length, final CharSequence alphabet)
	{
		Objects.requireNonNull(alphabet, "alphabet must not be null");
		if (length < 0)
		{
			throw new IllegalArgumentException("length must not be negative, but is " + length);
		}
		final String distinct = distinctCharacters(alphabet);
		final char[] drawn = new char[length];
		for (int i = 0; i < length; i++)
		{
			drawn[i] = distinct.charAt(SOURCE.nextInt(distinct.length()));
		}
		return drawn;
	}

	/**
	 * The characters of the given alphabet, each once, in the order of their first appearance
	 *
	 * @param alphabet
	 *            the alphabet
	 * @return the distinct characters
	 * @throws IllegalArgumentException
	 *             if the alphabet is empty or holds a surrogate
	 */
	private static String distinctCharacters(final CharSequence alphabet)
	{
		if (alphabet.isEmpty())
		{
			throw new IllegalArgumentException("alphabet must not be empty");
		}
		final StringBuilder distinct = new StringBuilder();
		for (int i = 0; i < alphabet.length(); i++)
		{
			final char character = alphabet.charAt(i);
			if (Character.isSurrogate(character))
			{
				throw new IllegalArgumentException("alphabet must not hold a surrogate, but holds "
					+ String.format("U+%04X", (int)character) + " at index " + i);
			}
			if (distinct.indexOf(String.valueOf(character)) < 0)
			{
				distinct.append(character);
			}
		}
		return distinct.toString();
	}
}
