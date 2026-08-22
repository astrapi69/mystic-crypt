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
package io.github.astrapi69.mystic.crypt.sha;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import io.github.astrapi69.crypt.api.algorithm.MessageDigestAlgorithm;

/**
 * The class {@link Sha3Hasher} provides SHA-3 hashing (FIPS 202) for the four fixed-length variants
 * SHA3-224, SHA3-256, SHA3-384 and SHA3-512, using the JDK's built-in implementation - no Bouncy
 * Castle involved. The API mirrors {@link Blake2bHasher}; the variant is selected via the
 * corresponding {@link MessageDigestAlgorithm} constant, and passing any non-SHA-3 constant is
 * rejected so this class can never silently compute MD5 or SHA-2 under a SHA-3 name.
 * <p>
 * SHA-3 is a different construction (Keccak sponge) from SHA-2 and is the NIST-standardised
 * alternative to it, not a replacement: SHA-2 is not broken. Use SHA-3 where a standard requires
 * it, where algorithm diversity from SHA-2 is wanted, or where its resistance to length-extension
 * attacks matters (SHA-2 without HMAC is vulnerable to them, SHA-3 is not).
 *
 * @author Asterios Raptis
 */
public final class Sha3Hasher
{

	/** The default variant, SHA3-256 */
	public static final MessageDigestAlgorithm DEFAULT_ALGORITHM = MessageDigestAlgorithm.SHA3_256;

	private static final String SHA3_CONSTANT_PREFIX = "SHA3_";

	private Sha3Hasher()
	{
	}

	/**
	 * Computes the SHA3-256 hash of the given data.
	 *
	 * @param data
	 *            the data to hash
	 * @return the 32-byte digest
	 * @throws IllegalArgumentException
	 *             if data is null
	 */
	public static byte[] hash(final byte[] data)
	{
		return hash(data, DEFAULT_ALGORITHM);
	}

	/**
	 * Computes the SHA-3 hash of the given data with the given variant.
	 *
	 * @param data
	 *            the data to hash
	 * @param algorithm
	 *            one of {@link MessageDigestAlgorithm#SHA3_224},
	 *            {@link MessageDigestAlgorithm#SHA3_256}, {@link MessageDigestAlgorithm#SHA3_384},
	 *            {@link MessageDigestAlgorithm#SHA3_512}
	 * @return the digest (28, 32, 48 or 64 bytes respectively)
	 * @throws IllegalArgumentException
	 *             if data or algorithm is null, or algorithm is not a SHA-3 variant
	 */
	public static byte[] hash(final byte[] data, final MessageDigestAlgorithm algorithm)
	{
		if (data == null)
		{
			throw new IllegalArgumentException("Data cannot be null");
		}
		return newDigest(algorithm).digest(data);
	}

	/**
	 * Computes the SHA3-256 hash of the given string.
	 *
	 * @param data
	 *            the string to hash
	 * @param charset
	 *            the charset to encode the string with
	 * @return the 32-byte digest
	 * @throws IllegalArgumentException
	 *             if data or charset is null
	 */
	public static byte[] hash(final String data, final Charset charset)
	{
		return hash(data, charset, DEFAULT_ALGORITHM);
	}

	/**
	 * Computes the SHA-3 hash of the given string with the given variant.
	 *
	 * @param data
	 *            the string to hash
	 * @param charset
	 *            the charset to encode the string with
	 * @param algorithm
	 *            the SHA-3 variant, see {@link #hash(byte[], MessageDigestAlgorithm)}
	 * @return the digest
	 * @throws IllegalArgumentException
	 *             if data, charset or algorithm is null, or algorithm is not a SHA-3 variant
	 */
	public static byte[] hash(final String data, final Charset charset,
		final MessageDigestAlgorithm algorithm)
	{
		if (data == null)
		{
			throw new IllegalArgumentException("Data cannot be null");
		}
		if (charset == null)
		{
			throw new IllegalArgumentException("Charset cannot be null");
		}
		return hash(data.getBytes(charset), algorithm);
	}

	/**
	 * Computes the SHA3-256 hash of the given string, encoded as UTF-8.
	 *
	 * @param data
	 *            the string to hash
	 * @return the 32-byte digest
	 * @throws IllegalArgumentException
	 *             if data is null
	 */
	public static byte[] hashUtf8(final String data)
	{
		return hash(data, StandardCharsets.UTF_8);
	}

	/**
	 * Computes the SHA-3 hash of the given string, encoded as UTF-8, with the given variant.
	 *
	 * @param data
	 *            the string to hash
	 * @param algorithm
	 *            the SHA-3 variant, see {@link #hash(byte[], MessageDigestAlgorithm)}
	 * @return the digest
	 * @throws IllegalArgumentException
	 *             if data or algorithm is null, or algorithm is not a SHA-3 variant
	 */
	public static byte[] hashUtf8(final String data, final MessageDigestAlgorithm algorithm)
	{
		return hash(data, StandardCharsets.UTF_8, algorithm);
	}

	private static MessageDigest newDigest(final MessageDigestAlgorithm algorithm)
	{
		if (algorithm == null)
		{
			throw new IllegalArgumentException("Algorithm cannot be null");
		}
		if (!algorithm.name().startsWith(SHA3_CONSTANT_PREFIX))
		{
			throw new IllegalArgumentException("Not a SHA-3 algorithm: " + algorithm);
		}
		try
		{
			return MessageDigest.getInstance(algorithm.getAlgorithm());
		}
		catch (final NoSuchAlgorithmException e)
		{
			// unreachable on any OpenJDK >= 9: all four SHA-3 variants ship in the SUN provider,
			// and this library requires JDK 25
			throw new IllegalStateException(
				"SHA-3 not available from the JDK: " + algorithm.getAlgorithm(), e);
		}
	}

}
