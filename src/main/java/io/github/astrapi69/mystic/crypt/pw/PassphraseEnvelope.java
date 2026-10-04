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
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import io.github.astrapi69.mystic.crypt.aead.KeyCommittingAeadEncryptor;
import io.github.astrapi69.mystic.crypt.secret.SecretBuffers;

/**
 * Seals something with a passphrase under a marker the caller chooses, so that a wrong passphrase
 * fails as a wrong passphrase and a file says which format it belongs to.
 * <p>
 * What comes out looks like this:
 *
 * <pre>
 * magic                   whatever the caller uses to recognise its own files
 * salt         16 bytes   drawn fresh every time
 * iterations    4 bytes   the cost of the key derivation, big endian
 * payload                 AES-GCM, key-committing
 * </pre>
 *
 * The key comes from PBKDF2-HMAC-SHA256 over that salt. Magic, salt and iteration count are the
 * cipher's associated data, so none of them can be changed without the result refusing to open, and
 * the recorded cost can be raised later without making today's files unreadable.
 * <p>
 * This is the construction mystic-crypt-ui has written its master-password database and its
 * file-crypt output with since 8.6, moved here because a second consumer cannot write that format
 * without copying application code (#160). The layout is unchanged, byte for byte, which is the
 * point: the files are already on disk.
 * <p>
 * It carries no version of its own. The caller's magic IS the format identifier, and a format that
 * needs a version has a header to put one in. The one marker that is therefore not available is
 * {@link PassphraseCryptor#MAGIC}: files in that layout exist, written by this library's own
 * command line since 13.2 and by lethenon 0.1.0, and they carry a version byte exactly where this
 * layout has the first byte of the salt. {@link PassphraseCryptor} stays as it is and reads them.
 * <p>
 * <b>The caller owns the passphrase array.</b> Every method here that takes a {@code char[]} reads
 * it and never modifies it - not on success, not on failure. Overwriting it is the caller's job,
 * once the call has returned, with {@link SecretBuffers#wipe(char[])}:
 *
 * <pre>
 * char[] passphrase = ...;
 * try
 * {
 * 	return PassphraseEnvelope.decrypt(magic, content, passphrase);
 * }
 * finally
 * {
 * 	SecretBuffers.wipe(passphrase);
 * }
 * </pre>
 *
 * This is the opposite of {@link PassphraseCryptor}, which overwrites the array it is given; a
 * caller moving from one to the other has to add the wipe, or the passphrase stays in memory after
 * every call. The promise is pinned by a test, so a later change that starts overwriting here fails
 * it rather than surprising a caller that still needs the array.
 */
public final class PassphraseEnvelope
{

	/** The length of the salt that goes into the key derivation */
	public static final int SALT_LENGTH = 16;

	/**
	 * How many rounds the key derivation costs for something written today. The current OWASP
	 * recommendation for PBKDF2-HMAC-SHA256; measured at about a tenth of a second
	 */
	public static final int ITERATIONS = 600_000;

	/** The length of the derived key in bits */
	public static final int KEY_LENGTH_BITS = 256;

	private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";

	private PassphraseEnvelope()
	{
	}

	/**
	 * The length of the header in front of the payload
	 *
	 * @param magic
	 *            the marker of the format
	 * @return the number of bytes before the payload starts
	 */
	public static int headerLength(final byte[] magic)
	{
		return magic.length + SALT_LENGTH + Integer.BYTES;
	}

	/**
	 * Whether the given content starts with the given marker
	 *
	 * @param content
	 *            the bytes to look at
	 * @param magic
	 *            the marker to look for
	 * @return true if the marker is there
	 */
	public static boolean hasMagic(final byte[] content, final byte[] magic)
	{
		return content != null && content.length >= magic.length
			&& Arrays.equals(Arrays.copyOf(content, magic.length), magic);
	}

	/**
	 * The key derivation cost recorded in the given content, which is what a reader has to derive
	 * with rather than the current {@link #ITERATIONS}
	 *
	 * @param magic
	 *            the marker of the format
	 * @param content
	 *            the sealed bytes
	 * @return the iteration count the content was written with
	 */
	public static int iterationsOf(final byte[] magic, final byte[] content)
	{
		return ByteBuffer.wrap(content, magic.length + SALT_LENGTH, Integer.BYTES).getInt();
	}

	/**
	 * Derives the key something is sealed with
	 *
	 * @param passphrase
	 *            the passphrase
	 * @param salt
	 *            the salt
	 * @param iterations
	 *            the iteration count
	 * @return the derived key
	 * @throws GeneralSecurityException
	 *             if the key cannot be derived
	 */
	public static SecretKey deriveKey(final String passphrase, final byte[] salt,
		final int iterations) throws GeneralSecurityException
	{
		byte[] keyBytes = withCharactersOf(passphrase,
			characters -> deriveKey(characters, salt, iterations).getEncoded());
		try
		{
			// the spec copies what it is given, so the array this method holds is its own to wipe
			return new SecretKeySpec(keyBytes, "AES");
		}
		finally
		{
			SecretBuffers.wipe(keyBytes);
		}
	}

	/**
	 * Derives the key something is sealed with, from characters rather than from a {@link String}.
	 * A String cannot be cleared and lives until the garbage collector gets to it, so a caller that
	 * holds the passphrase as a character array should not have to make one to use this
	 *
	 * @param passphrase
	 *            the passphrase, read and not modified; the caller overwrites it afterwards
	 * @param salt
	 *            the salt
	 * @param iterations
	 *            the iteration count
	 * @return the derived key
	 * @throws GeneralSecurityException
	 *             if the key cannot be derived
	 */
	public static SecretKey deriveKey(final char[] passphrase, final byte[] salt,
		final int iterations) throws GeneralSecurityException
	{
		PBEKeySpec keySpec = new PBEKeySpec(passphrase, salt, iterations, KEY_LENGTH_BITS);
		try
		{
			byte[] keyBytes = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM)
				.generateSecret(keySpec).getEncoded();
			return new SecretKeySpec(keyBytes, "AES");
		}
		finally
		{
			// the spec holds a copy of the passphrase; there is no reason to leave it lying around
			keySpec.clearPassword();
		}
	}

	/**
	 * Seals the given bytes with the given passphrase
	 *
	 * @param magic
	 *            the marker to put in front, not {@link PassphraseCryptor#MAGIC}
	 * @param plaintext
	 *            what to seal
	 * @param passphrase
	 *            the passphrase
	 * @return the sealed result, header included
	 * @throws GeneralSecurityException
	 *             if sealing fails
	 */
	public static byte[] encrypt(final byte[] magic, final byte[] plaintext,
		final String passphrase) throws GeneralSecurityException
	{
		return withCharactersOf(passphrase, characters -> encrypt(magic, plaintext, characters));
	}

	/**
	 * Seals the given bytes with a passphrase held as characters rather than as a {@link String},
	 * so that a caller that keeps it in a character array does not have to make an unwipeable copy
	 * to use it. The array is read, never modified: the caller owns it and overwrites it with
	 * {@link SecretBuffers#wipe(char[])} once this returns
	 *
	 * @param magic
	 *            the marker to put in front, not {@link PassphraseCryptor#MAGIC}
	 * @param plaintext
	 *            what to seal
	 * @param passphrase
	 *            the passphrase
	 * @return the sealed result, header included
	 * @throws GeneralSecurityException
	 *             if sealing fails
	 */
	public static byte[] encrypt(final byte[] magic, final byte[] plaintext,
		final char[] passphrase) throws GeneralSecurityException
	{
		byte[] salt = new byte[SALT_LENGTH];
		// deliberately not SecureRandom.getInstanceStrong(): on Linux that can resolve to the
		// blocking source, and sealing must never hang waiting for entropy. The default instance
		// reads from the non-blocking pool, which is the right source for a salt
		new SecureRandom().nextBytes(salt);
		return seal(magic, plaintext, passphrase, salt, ITERATIONS);
	}

	/**
	 * Opens what {@link #encrypt(byte[], byte[], String)} produced
	 *
	 * @param magic
	 *            the marker the content must start with
	 * @param content
	 *            the sealed bytes
	 * @param passphrase
	 *            the passphrase
	 * @return the plaintext
	 * @throws SecurityException
	 *             if the content is of this format but does not open: the passphrase is wrong or
	 *             the data was altered
	 * @throws IllegalArgumentException
	 *             if the content is not of this format at all, or is truncated
	 * @throws GeneralSecurityException
	 *             if the key cannot be derived
	 */
	public static byte[] decrypt(final byte[] magic, final byte[] content, final String passphrase)
		throws GeneralSecurityException
	{
		return withCharactersOf(passphrase, characters -> decrypt(magic, content, characters));
	}

	/**
	 * Opens what {@link #encrypt(byte[], byte[], char[])} produced, with a passphrase held as
	 * characters rather than as a {@link String}. The array is read, never modified: the caller
	 * owns it and overwrites it with {@link SecretBuffers#wipe(char[])} once this returns
	 *
	 * @param magic
	 *            the marker the content must start with
	 * @param content
	 *            the sealed bytes
	 * @param passphrase
	 *            the passphrase
	 * @return the plaintext
	 * @throws SecurityException
	 *             if the content is of this format but does not open: the passphrase is wrong or
	 *             the data was altered
	 * @throws IllegalArgumentException
	 *             if the content is not of this format at all, or is truncated
	 * @throws GeneralSecurityException
	 *             if the key cannot be derived
	 */
	public static byte[] decrypt(final byte[] magic, final byte[] content, final char[] passphrase)
		throws GeneralSecurityException
	{
		refuseTheReservedMarker(magic);
		if (!hasMagic(content, magic))
		{
			throw new IllegalArgumentException(
				"this is not something this envelope sealed: the marker is missing");
		}
		int headerLength = headerLength(magic);
		if (content.length <= headerLength)
		{
			throw new IllegalArgumentException(
				"truncated: the marker is there but there is no content behind it");
		}
		byte[] header = Arrays.copyOf(content, headerLength);
		byte[] salt = Arrays.copyOfRange(header, magic.length, magic.length + SALT_LENGTH);
		int iterations = iterationsOf(magic, content);
		byte[] payload = Arrays.copyOfRange(content, headerLength, content.length);
		SecretKey key = deriveKey(passphrase, salt, iterations);
		try
		{
			// the header is the associated data, so a changed salt or iteration count breaks the
			// tag
			return new KeyCommittingAeadEncryptor(key).decrypt(payload, header);
		}
		catch (Exception openingFailed)
		{
			// everything that fails from here on is "this is ours and it would not open" - a wrong
			// passphrase fails the key commitment, an altered payload fails the tag - and the
			// caller
			// tells that apart from "this is not ours", above, by the exception type alone. The
			// same contract as PassphraseCryptor, which the command line's exit codes rest on
			throw new SecurityException(
				"could not decrypt: the passphrase is wrong or the data was altered",
				openingFailed);
		}
	}

	/**
	 * Seals with a salt and a cost the caller names, which is what reading a file written with an
	 * older cost needs.
	 * <p>
	 * Not public: a caller that chooses the salt can reuse one, and two files sealed with the same
	 * passphrase and the same salt are comparable. {@link #encrypt(byte[], byte[], char[])} draws a
	 * fresh one, every time, and that is the only way in from outside
	 *
	 * @param magic
	 *            the marker to put in front
	 * @param plaintext
	 *            what to seal
	 * @param passphrase
	 *            the passphrase
	 * @param salt
	 *            the salt to derive with
	 * @param iterations
	 *            the cost to derive with and to record
	 * @return the sealed result, header included
	 * @throws GeneralSecurityException
	 *             if sealing fails
	 */
	static byte[] seal(final byte[] magic, final byte[] plaintext, final char[] passphrase,
		final byte[] salt, final int iterations) throws GeneralSecurityException
	{
		refuseTheReservedMarker(magic);
		byte[] header = ByteBuffer.allocate(headerLength(magic)).put(magic).put(salt)
			.putInt(iterations).array();
		byte[] payload = sealPayload(deriveKey(passphrase, salt, iterations), plaintext, header);
		return ByteBuffer.allocate(header.length + payload.length).put(header).put(payload).array();
	}

	/**
	 * Encrypts the payload with the header as associated data.
	 * <p>
	 * {@link KeyCommittingAeadEncryptor} declares {@code throws Exception} through the cryptor
	 * hierarchy it inherits from; everything a cipher can fail with is a
	 * {@link GeneralSecurityException} or a runtime exception, and those pass through unchanged.
	 * Anything else checked is wrapped in one, so this class declares no more than the JDK's
	 * security exception (#182)
	 *
	 * @param key
	 *            the derived key
	 * @param plaintext
	 *            what to encrypt
	 * @param header
	 *            the associated data
	 * @return the payload
	 * @throws GeneralSecurityException
	 *             if the cipher cannot run
	 */
	private static byte[] sealPayload(final SecretKey key, final byte[] plaintext,
		final byte[] header) throws GeneralSecurityException
	{
		try
		{
			return new KeyCommittingAeadEncryptor(key).encrypt(plaintext, header);
		}
		catch (GeneralSecurityException | RuntimeException asItWas)
		{
			throw asItWas;
		}
		catch (Exception notASecurityFailure)
		{
			throw new GeneralSecurityException(
				"could not seal: " + notASecurityFailure.getMessage(), notASecurityFailure);
		}
	}

	/**
	 * Refuses the one marker this layout cannot carry, by name.
	 * <p>
	 * A file starting with {@link PassphraseCryptor#MAGIC} is a file in that layout, which has a
	 * version byte where this one has the first byte of the salt. Letting a caller seal under the
	 * same marker would make the two indistinguishable in one file out of 256, and no reader could
	 * be written that is right about both
	 *
	 * @param magic
	 *            the marker the caller wants to use
	 */
	private static void refuseTheReservedMarker(final byte[] magic)
	{
		if (Arrays.equals(magic, PassphraseCryptor.MAGIC))
		{
			throw new IllegalArgumentException(
				"the marker '" + new String(PassphraseCryptor.MAGIC, StandardCharsets.US_ASCII)
					+ "' belongs to PassphraseCryptor, whose files carry a version byte where this "
					+ "layout carries the salt - pick another marker for this format");
		}
	}

	/**
	 * Runs the given operation on the characters of a {@link String} passphrase and overwrites the
	 * array afterwards.
	 * <p>
	 * The String itself stays what it is - it cannot be overwritten, which is the whole reason the
	 * character overloads exist. What this avoids is a SECOND unwipeable copy for callers that
	 * still have to hand one over, and it keeps the two overloads on one implementation so they
	 * cannot drift apart
	 *
	 * @param passphrase
	 *            the passphrase
	 * @param operation
	 *            what to do with its characters
	 * @return whatever the operation returned
	 * @throws GeneralSecurityException
	 *             if the operation fails
	 */
	private static byte[] withCharactersOf(final String passphrase,
		final PassphraseOperation operation) throws GeneralSecurityException
	{
		char[] characters = passphrase.toCharArray();
		try
		{
			return operation.apply(characters);
		}
		finally
		{
			SecretBuffers.wipe(characters);
		}
	}

	/** What {@link #withCharactersOf(String, PassphraseOperation)} runs on the characters */
	@FunctionalInterface
	private interface PassphraseOperation
	{
		byte[] apply(char[] passphrase) throws GeneralSecurityException;
	}
}
