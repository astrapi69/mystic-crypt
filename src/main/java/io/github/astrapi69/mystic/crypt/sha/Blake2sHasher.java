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
import java.security.Security;

import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The class {@link Blake2sHasher} provides BLAKE2s hashing functionality using Bouncy Castle.
 * BLAKE2s is optimized for 8-32 bit platforms and embedded systems, providing excellent performance
 * on smaller architectures while maintaining strong security properties.
 * 
 * <p>
 * BLAKE2s supports variable output lengths from 1 to 32 bytes (256 bits). The default is 32 bytes.
 * </p>
 * 
 * @author Asterios Raptis
 */
public final class Blake2sHasher
{

	static
	{
		// Register Bouncy Castle provider if not already registered
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	/** Default digest length in bytes (32 bytes = 256 bits) */
	public static final int DEFAULT_DIGEST_LENGTH = 32;

	/** Minimum digest length in bytes */
	public static final int MIN_DIGEST_LENGTH = 1;

	/** Maximum digest length in bytes (256 bits) */
	public static final int MAX_DIGEST_LENGTH = 32;

	private Blake2sHasher()
	{
	}

	/**
	 * Computes the BLAKE2s hash of the given data with default digest length (32 bytes).
	 *
	 * @param data
	 *            the data to hash
	 * @return the hash as a byte array (32 bytes)
	 * @throws IllegalArgumentException
	 *             if data is null
	 */
	public static byte[] hash(final byte[] data)
	{
		return hash(data, DEFAULT_DIGEST_LENGTH);
	}

	/**
	 * Computes the BLAKE2s hash of the given data with specified digest length.
	 *
	 * @param data
	 *            the data to hash
	 * @param digestLength
	 *            the desired digest length in bytes (1-32)
	 * @return the hash as a byte array
	 * @throws IllegalArgumentException
	 *             if data is null or digestLength is out of range
	 */
	public static byte[] hash(final byte[] data, final int digestLength)
	{
		if (data == null)
		{
			throw new IllegalArgumentException("Data cannot be null");
		}
		if (digestLength < MIN_DIGEST_LENGTH || digestLength > MAX_DIGEST_LENGTH)
		{
			throw new IllegalArgumentException(
				"Digest length must be between " + MIN_DIGEST_LENGTH + " and " + MAX_DIGEST_LENGTH);
		}

		final Blake2sDigest digest = new Blake2sDigest(digestLength * 8);
		digest.update(data, 0, data.length);

		final byte[] result = new byte[digestLength];
		digest.doFinal(result, 0);

		return result;
	}

	/**
	 * Computes the BLAKE2s hash of the given string with default digest length.
	 *
	 * @param data
	 *            the string to hash
	 * @param charset
	 *            the charset to use for encoding
	 * @return the hash as a byte array (32 bytes)
	 * @throws IllegalArgumentException
	 *             if data or charset is null
	 */
	public static byte[] hash(final String data, final Charset charset)
	{
		return hash(data, charset, DEFAULT_DIGEST_LENGTH);
	}

	/**
	 * Computes the BLAKE2s hash of the given string with specified digest length.
	 *
	 * @param data
	 *            the string to hash
	 * @param charset
	 *            the charset to use for encoding
	 * @param digestLength
	 *            the desired digest length in bytes (1-32)
	 * @return the hash as a byte array
	 * @throws IllegalArgumentException
	 *             if data, charset is null or digestLength is out of range
	 */
	public static byte[] hash(final String data, final Charset charset, final int digestLength)
	{
		if (data == null)
		{
			throw new IllegalArgumentException("Data cannot be null");
		}
		if (charset == null)
		{
			throw new IllegalArgumentException("Charset cannot be null");
		}

		return hash(data.getBytes(charset), digestLength);
	}

	/**
	 * Computes the BLAKE2s hash of the given string with UTF-8 encoding.
	 *
	 * @param data
	 *            the string to hash
	 * @return the hash as a byte array (32 bytes)
	 */
	public static byte[] hashUtf8(final String data)
	{
		return hash(data, StandardCharsets.UTF_8);
	}

	/**
	 * Computes the BLAKE2s hash of the given string with UTF-8 encoding and specified digest
	 * length.
	 *
	 * @param data
	 *            the string to hash
	 * @param digestLength
	 *            the desired digest length in bytes (1-32)
	 * @return the hash as a byte array
	 */
	public static byte[] hashUtf8(final String data, final int digestLength)
	{
		return hash(data, StandardCharsets.UTF_8, digestLength);
	}

	/**
	 * Computes the BLAKE2s hash of the given data with an optional key (keyed hashing mode). Keyed
	 * BLAKE2s can be used as a MAC (Message Authentication Code).
	 *
	 * @param data
	 *            the data to hash
	 * @param key
	 *            the key for keyed hashing (max 32 bytes), or null for unkeyed hashing
	 * @param digestLength
	 *            the desired digest length in bytes (1-32)
	 * @return the hash as a byte array
	 * @throws IllegalArgumentException
	 *             if key is too long or digestLength is out of range
	 */
	public static byte[] hashWithKey(final byte[] data, final byte[] key, final int digestLength)
	{
		if (data == null)
		{
			throw new IllegalArgumentException("Data cannot be null");
		}
		if (key != null && key.length > 32)
		{
			throw new IllegalArgumentException("Key cannot be longer than 32 bytes");
		}
		if (digestLength < MIN_DIGEST_LENGTH || digestLength > MAX_DIGEST_LENGTH)
		{
			throw new IllegalArgumentException(
				"Digest length must be between " + MIN_DIGEST_LENGTH + " and " + MAX_DIGEST_LENGTH);
		}

		final Blake2sDigest digest;
		if (key != null)
		{
			// Blake2sDigest(byte[]) hardcodes a 32-byte output regardless of the
			// requested digestLength, which throws OutputLengthException from doFinal
			// below whenever digestLength < 32; the keyed+digestLength constructor
			// respects the requested length instead.
			digest = new Blake2sDigest(key, digestLength, null, null);
		}
		else
		{
			digest = new Blake2sDigest(digestLength * 8);
		}
		digest.update(data, 0, data.length);

		final byte[] result = new byte[digestLength];
		digest.doFinal(result, 0);

		return result;
	}

	/**
	 * Computes the BLAKE2s hash with key for string data with UTF-8 encoding.
	 *
	 * @param data
	 *            the string to hash
	 * @param key
	 *            the key for keyed hashing (max 32 bytes)
	 * @param digestLength
	 *            the desired digest length in bytes (1-32)
	 * @return the hash as a byte array
	 */
	public static byte[] hashUtf8WithKey(final String data, final byte[] key,
		final int digestLength)
	{
		return hashWithKey(data.getBytes(StandardCharsets.UTF_8), key, digestLength);
	}

}
