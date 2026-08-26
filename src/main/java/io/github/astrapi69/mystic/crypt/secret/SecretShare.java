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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

/**
 * One line of a secret split, and the text format it is written in.
 * <p>
 * Shamir's scheme by itself has no integrity check: combining shares that belong to different
 * splits, or fewer shares than the split's threshold, silently yields a wrong secret instead of
 * failing. This format carries what is needed to catch both.
 *
 * <pre>
 * mcs1:&lt;splitId&gt;:&lt;threshold&gt;:&lt;total&gt;:&lt;index&gt;:&lt;value&gt;:&lt;checksum&gt;
 * </pre>
 *
 * <ul>
 * <li>{@code splitId} is random per split, so shares of two different splits cannot be combined by
 * accident</li>
 * <li>{@code threshold} travels with every share, so "fewer shares than the split needs" is a
 * statement the tool can make rather than a wrong secret it hands back</li>
 * <li>{@code checksum} covers the fields before it, so a share mistyped while being copied is
 * rejected where it is entered</li>
 * </ul>
 *
 * The checksum deliberately covers the share, not the secret: a digest of the secret in every share
 * would let anyone holding a single share test guesses against it offline.
 */
public final class SecretShare
{

	/** The prefix and format version every share line starts with. */
	public static final String PREFIX = "mcs1";

	/** The field separator inside a share line. */
	private static final String SEPARATOR = ":";

	/** Number of fields a well formed share line has. */
	private static final int FIELD_COUNT = 7;

	/** Length in bytes of the truncated digest used as the per-share checksum. */
	private static final int CHECKSUM_LENGTH = 4;

	/** The digest the per-share checksum is computed with. */
	private static final String CHECKSUM_ALGORITHM = "SHA-256";

	/** Length in bytes of the random identifier shared by all shares of one split. */
	static final int SPLIT_ID_LENGTH = 8;

	private final String splitId;
	private final int threshold;
	private final int total;
	private final int index;
	private final byte[] value;

	/**
	 * Instantiates a new {@link SecretShare}.
	 *
	 * @param splitId
	 *            the identifier common to all shares of one split
	 * @param threshold
	 *            the number of shares needed to reconstruct the secret
	 * @param total
	 *            the number of shares the split produced
	 * @param index
	 *            the 1-based index of this share
	 * @param value
	 *            the share value bytes
	 */
	public SecretShare(final String splitId, final int threshold, final int total, final int index,
		final byte[] value)
	{
		this.splitId = splitId;
		this.threshold = threshold;
		this.total = total;
		this.index = index;
		this.value = value.clone();
	}

	/**
	 * Gets the identifier common to all shares of one split.
	 *
	 * @return the split identifier
	 */
	public String getSplitId()
	{
		return splitId;
	}

	/**
	 * Gets the number of shares needed to reconstruct the secret.
	 *
	 * @return the threshold
	 */
	public int getThreshold()
	{
		return threshold;
	}

	/**
	 * Gets the number of shares the split produced.
	 *
	 * @return the total number of shares
	 */
	public int getTotal()
	{
		return total;
	}

	/**
	 * Gets the 1-based index of this share.
	 *
	 * @return the share index
	 */
	public int getIndex()
	{
		return index;
	}

	/**
	 * Gets the share value bytes.
	 *
	 * @return a copy of the share value bytes
	 */
	public byte[] getValue()
	{
		return value.clone();
	}

	/**
	 * Renders this share as the single line that a holder keeps.
	 *
	 * @return the share line
	 */
	public String encode()
	{
		final String body = body();
		return body + SEPARATOR + checksumOf(body);
	}

	/**
	 * Parses a share line produced by {@link #encode()}.
	 *
	 * @param line
	 *            the share line
	 * @return the parsed share
	 * @throws IllegalArgumentException
	 *             if the line is not a share line, or its checksum does not match
	 */
	public static SecretShare decode(final String line)
	{
		final String trimmed = line == null ? "" : line.trim();
		final String[] fields = trimmed.split(SEPARATOR, -1);
		if (fields.length != FIELD_COUNT || !PREFIX.equals(fields[0]))
		{
			throw new IllegalArgumentException("not a mystic-crypt share: a share line looks like '"
				+ PREFIX + ":<splitId>:<threshold>:<total>:<index>:<value>:<checksum>' but was '"
				+ trimmed + "'");
		}
		final SecretShare share = new SecretShare(fields[1], parseNumber(fields[2], "threshold"),
			parseNumber(fields[3], "total"), parseNumber(fields[4], "index"),
			decodeValue(fields[5]));
		final String expected = checksumOf(share.body());
		if (!expected.equals(fields[6]))
		{
			throw new IllegalArgumentException("share " + fields[4] + " of split " + fields[1]
				+ " does not match its own checksum, so it was altered or mistyped");
		}
		return share;
	}

	private String body()
	{
		return PREFIX + SEPARATOR + splitId + SEPARATOR + threshold + SEPARATOR + total + SEPARATOR
			+ index + SEPARATOR + Base64.getUrlEncoder().withoutPadding().encodeToString(value);
	}

	private static int parseNumber(final String field, final String name)
	{
		try
		{
			return Integer.parseInt(field);
		}
		catch (final NumberFormatException notANumber)
		{
			throw new IllegalArgumentException(
				"the " + name + " of a share must be a number, but was '" + field + "'",
				notANumber);
		}
	}

	private static byte[] decodeValue(final String field)
	{
		try
		{
			return Base64.getUrlDecoder().decode(field);
		}
		catch (final IllegalArgumentException notBase64)
		{
			throw new IllegalArgumentException(
				"the value of a share must be base64url, but was '" + field + "'", notBase64);
		}
	}

	private static String checksumOf(final String body)
	{
		return checksumOf(body, CHECKSUM_ALGORITHM);
	}

	/**
	 * Computes the per-share checksum with the given digest algorithm. The algorithm is a parameter
	 * only so that the compiler-mandated handling of {@link NoSuchAlgorithmException} - which the
	 * fixed {@code SHA-256} can never actually trigger - stays reachable and testable through a
	 * bogus name, the same way {@code Pbkdf2Support#rawHash} does it.
	 *
	 * @param body
	 *            the share line up to but excluding the checksum field
	 * @param algorithm
	 *            the {@link MessageDigest} algorithm name
	 * @return the truncated digest, hex encoded
	 * @throws IllegalStateException
	 *             if the algorithm is unavailable
	 */
	static String checksumOf(final String body, final String algorithm)
	{
		try
		{
			final byte[] digest = MessageDigest.getInstance(algorithm)
				.digest(body.getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(Arrays.copyOf(digest, CHECKSUM_LENGTH));
		}
		catch (final NoSuchAlgorithmException impossible)
		{
			throw new IllegalStateException(impossible);
		}
	}
}
