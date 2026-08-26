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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import io.github.astrapi69.mystic.crypt.aead.KeyCommittingAeadEncryptor;
import io.github.astrapi69.random.number.RandomByteFactory;

/**
 * Passphrase-based authenticated encryption of arbitrary bytes, the operation behind the
 * {@code encrypt} and {@code decrypt} commands.
 * <p>
 * A key is derived from the passphrase with PBKDF2-HMAC-SHA256 over a salt that is fresh for every
 * call, and the payload is sealed with AES-GCM through {@link KeyCommittingAeadEncryptor}, so a
 * wrong passphrase is rejected by the key commitment instead of producing plausible looking
 * rubbish.
 * <p>
 * The output carries its own header:
 *
 * <pre>
 * "MCRYPT" (6) | version (1) | iterations (4, big endian) | salt (16) | AES-GCM payload
 * </pre>
 *
 * The marker makes the format recognisable ({@link #isEncrypted(byte[])}) and the version byte
 * leaves room to change the construction later. The iteration count travels with the payload, so
 * raising {@link #DEFAULT_ITERATIONS} does not strand anything encrypted with the old default.
 * <p>
 * As everywhere in this package, the given passphrase array is zeroed before returning, on success
 * and on failure alike; callers must not reuse it.
 */
public final class PassphraseCryptor
{

	/** The marker every output starts with, so the format can be recognised. */
	public static final byte[] MAGIC = { 'M', 'C', 'R', 'Y', 'P', 'T' };

	/** The version of the format described in the class javadoc. */
	public static final byte FORMAT_VERSION = 1;

	/** Salt length in bytes. */
	public static final int SALT_LENGTH = 16;

	/** Length of the header that precedes the AES-GCM payload. */
	public static final int HEADER_LENGTH = MAGIC.length + 1 + Integer.BYTES + SALT_LENGTH;

	/**
	 * Number of PBKDF2 iterations for new output, per the OWASP Password Storage Cheat Sheet
	 * guidance for PBKDF2-HMAC-SHA256.
	 */
	public static final int DEFAULT_ITERATIONS = 600_000;

	/** Derived key length in bits, an AES-256 key. */
	private static final int KEY_LENGTH_BITS = 256;

	private PassphraseCryptor()
	{
	}

	/**
	 * Encrypts the given bytes with a key derived from the given passphrase.
	 *
	 * @param passphrase
	 *            the passphrase, zeroed before this method returns
	 * @param plain
	 *            the bytes to encrypt
	 * @return the header followed by the AES-GCM payload
	 */
	public static byte[] encrypt(final char[] passphrase, final byte[] plain)
	{
		try
		{
			final byte[] salt = RandomByteFactory.randomByteArray(SALT_LENGTH);
			final SecretKey key = deriveKey(passphrase, salt, DEFAULT_ITERATIONS);
			final byte[] payload = new KeyCommittingAeadEncryptor(key).encrypt(plain);
			return ByteBuffer.allocate(HEADER_LENGTH + payload.length).put(MAGIC)
				.put(FORMAT_VERSION).putInt(DEFAULT_ITERATIONS).put(salt).put(payload).array();
		}
		catch (final Exception sealingFailed)
		{
			throw new IllegalStateException(
				"could not encrypt the given input: " + sealingFailed.getMessage(), sealingFailed);
		}
		finally
		{
			Arrays.fill(passphrase, '\0');
		}
	}

	/**
	 * Decrypts what {@link #encrypt(char[], byte[])} produced.
	 *
	 * @param passphrase
	 *            the passphrase, zeroed before this method returns
	 * @param encrypted
	 *            the header followed by the AES-GCM payload
	 * @return the decrypted bytes
	 * @throws IllegalArgumentException
	 *             if the input does not carry this format's header
	 * @throws SecurityException
	 *             if the passphrase is wrong or the payload was altered
	 */
	public static byte[] decrypt(final char[] passphrase, final byte[] encrypted)
	{
		try
		{
			// iterationsOf checks the header, and it does so outside the catch below on purpose:
			// "this is not our format at all" is a different answer from "this is our format and
			// it would not open", and the caller distinguishes the two by exception type
			final int iterations = iterationsOf(encrypted);
			final byte[] salt = Arrays.copyOfRange(encrypted, MAGIC.length + 1 + Integer.BYTES,
				HEADER_LENGTH);
			final byte[] payload = Arrays.copyOfRange(encrypted, HEADER_LENGTH, encrypted.length);
			final SecretKey key = deriveKey(passphrase, salt, iterations);
			try
			{
				return new KeyCommittingAeadEncryptor(key).decrypt(payload);
			}
			catch (final Exception openingFailed)
			{
				throw new SecurityException(
					"could not decrypt: the passphrase is wrong or the data was altered",
					openingFailed);
			}
		}
		finally
		{
			Arrays.fill(passphrase, '\0');
		}
	}

	/**
	 * Answers whether the given bytes start with this format's marker and version. Used to tell an
	 * encrypted file from any other file before asking for a passphrase.
	 *
	 * @param candidate
	 *            the bytes to inspect
	 * @return true if the bytes carry this format's header
	 */
	public static boolean isEncrypted(final byte[] candidate)
	{
		if (candidate == null || candidate.length < HEADER_LENGTH)
		{
			return false;
		}
		return Arrays.equals(Arrays.copyOf(candidate, MAGIC.length), MAGIC)
			&& candidate[MAGIC.length] == FORMAT_VERSION;
	}

	/**
	 * Reads the PBKDF2 iteration count the given output was produced with.
	 *
	 * @param encrypted
	 *            the encrypted bytes
	 * @return the iteration count stored in the header
	 * @throws IllegalArgumentException
	 *             if the input does not carry this format's header
	 */
	public static int iterationsOf(final byte[] encrypted)
	{
		requireOwnFormat(encrypted);
		return ByteBuffer.wrap(encrypted, MAGIC.length + 1, Integer.BYTES).getInt();
	}

	private static void requireOwnFormat(final byte[] encrypted)
	{
		if (!isEncrypted(encrypted))
		{
			throw new IllegalArgumentException(
				"not a mystic-crypt encrypted input: it does not start with the marker '"
					+ new String(MAGIC, StandardCharsets.US_ASCII) + "' and format version "
					+ FORMAT_VERSION);
		}
	}

	private static SecretKey deriveKey(final char[] passphrase, final byte[] salt,
		final int iterations)
	{
		final byte[] keyBytes = Pbkdf2Support.deriveKey(passphrase, salt, iterations,
			KEY_LENGTH_BITS);
		try
		{
			return new SecretKeySpec(keyBytes, "AES");
		}
		finally
		{
			// SecretKeySpec copies the bytes it is given, so nothing observable changes whether
			// this wipe happens or not - it is here because leaving derived key material in a
			// live array is the kind of thing that only becomes visible in a heap dump. PIT
			// reports removing it as a surviving mutant for exactly that reason; see
			// docs/COVERAGE_EXCEPTIONS.md.
			Arrays.fill(keyBytes, (byte)0);
		}
	}
}
