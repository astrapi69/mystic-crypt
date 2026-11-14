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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The reader of every format a file sealed with a passphrase comes in across this family (#306,
 * astrapi69/mystic-crypt-ui#877): the window's {@code MCFILE1}, the command line's {@code MCFILE},
 * and the released {@code MCRYPT}. It starts with what the window really wrote.
 */
class PassphraseFileFormatTest
{

	private static final char[] PASSPHRASE = "a passphrase for the reader".toCharArray();

	private static final byte[] PLAINTEXT = "what was sealed".getBytes(StandardCharsets.UTF_8);

	private static final byte[] MCFILE_MAGIC = "MCFILE".getBytes(StandardCharsets.US_ASCII);

	private static final byte[] MCFILE1_MAGIC = "MCFILE1".getBytes(StandardCharsets.US_ASCII);

	@Test
	void aFileTheWindowWrote_isAnMcfile1AndOpens() throws Exception
	{
		byte[] windowFile = WindowFixtures.fileBytes();

		assertEquals(Optional.of(PassphraseFileFormat.MCFILE1),
			PassphraseFileFormat.of(windowFile));
		assertArrayEquals(WindowFixtures.filePlaintext(),
			PassphraseFileFormat.open(windowFile, WindowFixtures.PASSPHRASE.toCharArray()));
	}

	@Test
	void aFileTheWindowWrote_isNotTriedAsAnMcfile() throws Exception
	{
		// read as an MCFILE its count is 1 124 075 815: develop's decrypt derived that long, 269.6
		// s
		// with the right passphrase and 274.2 s with a wrong one, and then said it was wrong
		assertEquals(List.of(PassphraseFileFormat.MCFILE1),
			PassphraseFileFormat.readingsOf(WindowFixtures.fileBytes()));
	}

	@Test
	void aTextTheWindowWrote_isAnMcfile1AndOpens() throws Exception
	{
		byte[] windowText = WindowFixtures.textBytes();

		assertEquals(Optional.of(PassphraseFileFormat.MCFILE1),
			PassphraseFileFormat.of(windowText));
		assertEquals(WindowFixtures.TEXT_PLAINTEXT,
			new String(
				PassphraseFileFormat.open(windowText, WindowFixtures.PASSPHRASE.toCharArray()),
				StandardCharsets.UTF_8));
	}

	/**
	 * Content in one format, sealed the way its writer seals it
	 *
	 * @param format
	 *            the format
	 * @param content
	 *            the sealed bytes
	 */
	record Sealed(PassphraseFileFormat format, byte[] content) {
		@Override
		public String toString()
		{
			return format.name();
		}
	}

	static Stream<Sealed> sealedInEveryFormat() throws Exception
	{
		return Stream.of(
			new Sealed(PassphraseFileFormat.MCFILE,
				PassphraseEnvelope.encrypt(MCFILE_MAGIC, PLAINTEXT, PASSPHRASE)),
			new Sealed(PassphraseFileFormat.MCFILE1,
				PassphraseEnvelope.encrypt(MCFILE1_MAGIC, PLAINTEXT, PASSPHRASE)),
			new Sealed(PassphraseFileFormat.MCRYPT,
				PassphraseCryptor.encrypt(PASSPHRASE.clone(), PLAINTEXT)));
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("sealedInEveryFormat")
	void contentInEveryFormat_isToldByItsHeaderAndOpens(final Sealed sealed) throws Exception
	{
		assertEquals(Optional.of(sealed.format()), PassphraseFileFormat.of(sealed.content()));
		assertArrayEquals(PLAINTEXT, PassphraseFileFormat.open(sealed.content(), PASSPHRASE));
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("sealedInEveryFormat")
	void aWrongPassphrase_isRefusedAsOursButNotOpening(final Sealed sealed)
	{
		assertThrows(SecurityException.class,
			() -> PassphraseFileFormat.open(sealed.content(), "wrong".toCharArray()));
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("sealedInEveryFormat")
	void thePassphrase_isReadAndLeftAsItWas(final Sealed sealed) throws Exception
	{
		char[] passphrase = PASSPHRASE.clone();

		PassphraseFileFormat.open(sealed.content(), passphrase);

		assertArrayEquals(PASSPHRASE, passphrase,
			"the caller owns the array, as with PassphraseEnvelope, also for MCRYPT");
	}

	static Stream<byte[]> notSealed()
	{
		return Stream.of(null, new byte[0], "MCFIL".getBytes(StandardCharsets.US_ASCII),
			"just a text file".getBytes(StandardCharsets.US_ASCII),
			"MCRDB2 is the vault, not a file".getBytes(StandardCharsets.US_ASCII));
	}

	@ParameterizedTest
	@MethodSource("notSealed")
	void contentInNoFormat_hasNoFormatAndIsRefusedNamingTheMarkers(final byte[] content)
	{
		assertEquals(Optional.empty(), PassphraseFileFormat.of(content));

		IllegalArgumentException refusal = assertThrows(IllegalArgumentException.class,
			() -> PassphraseFileFormat.open(content, PASSPHRASE));

		assertTrue(
			refusal.getMessage().contains("marker")
				&& refusal.getMessage().contains("MCFILE, MCFILE1 or MCRYPT"),
			refusal.getMessage());
	}

	@Test
	void aMarkerWithNothingBehindIt_isRefusedAsTruncated()
	{
		IllegalArgumentException refusal = assertThrows(IllegalArgumentException.class,
			() -> PassphraseFileFormat.open(MCFILE1_MAGIC, PASSPHRASE));

		assertTrue(refusal.getMessage().contains("truncated"), refusal.getMessage());
	}

	@Test
	void theMarkerOfMcrypt_isPassphraseCryptorsOwn()
	{
		byte[] sealed = PassphraseCryptor.encrypt(PASSPHRASE.clone(), PLAINTEXT);

		assertArrayEquals(PassphraseCryptor.MAGIC, Arrays.copyOf(sealed, 6));
		assertEquals(Optional.of(PassphraseFileFormat.MCRYPT), PassphraseFileFormat.of(sealed));
	}

	/**
	 * An {@code MCFILE} whose salt begins with the byte {@code '1'} starts with {@code MCFILE1}:
	 * one file in 256 that {@code encrypt} writes. Read as an {@code MCFILE1}, its iteration count
	 * is the real one shifted by a byte, 600 000 * 256 plus a byte of the payload
	 */
	@Test
	void anMcfileWhoseSaltBeginsWithOne_isAnMcfileAndOpens() throws Exception
	{
		byte[] salt = saltWith(0, (byte)'1');
		byte[] sealed = PassphraseEnvelope.seal(MCFILE_MAGIC, PLAINTEXT, PASSPHRASE, salt,
			PassphraseEnvelope.ITERATIONS);
		assertArrayEquals(MCFILE1_MAGIC, Arrays.copyOf(sealed, 7), "the header reads MCFILE1");

		assertEquals(List.of(PassphraseFileFormat.MCFILE), PassphraseFileFormat.readingsOf(sealed));
		assertEquals(Optional.of(PassphraseFileFormat.MCFILE), PassphraseFileFormat.of(sealed));
		assertArrayEquals(PLAINTEXT, PassphraseFileFormat.open(sealed, PASSPHRASE));
		assertThrows(SecurityException.class,
			() -> PassphraseFileFormat.open(sealed, "wrong".toCharArray()));
	}

	/**
	 * Every {@code MCFILE1} starts with {@code MCFILE}. Read as an {@code MCFILE}, its iteration
	 * count is {@code salt[15] * 2^24 + 2343}: beyond belief unless the last salt byte is 0
	 */
	@Test
	void anMcfile1WhoseSaltEndsWithZero_isTriedAsAnMcfile1First() throws Exception
	{
		byte[] sealed = PassphraseEnvelope.seal(MCFILE1_MAGIC, PLAINTEXT, PASSPHRASE,
			saltWith(15, (byte)0), PassphraseEnvelope.ITERATIONS);

		assertEquals(List.of(PassphraseFileFormat.MCFILE1, PassphraseFileFormat.MCFILE),
			PassphraseFileFormat.readingsOf(sealed));
		assertEquals(Optional.of(PassphraseFileFormat.MCFILE1), PassphraseFileFormat.of(sealed));
		assertArrayEquals(PLAINTEXT, PassphraseFileFormat.open(sealed, PASSPHRASE));
		assertThrows(SecurityException.class,
			() -> PassphraseFileFormat.open(sealed, "wrong".toCharArray()));
	}

	@Test
	void anMcfile1WhoseSaltEndsWithOne_isNotTriedAsAnMcfileAtAll() throws Exception
	{
		byte[] sealed = PassphraseEnvelope.seal(MCFILE1_MAGIC, PLAINTEXT, PASSPHRASE,
			saltWith(15, (byte)1), PassphraseEnvelope.ITERATIONS);

		assertEquals(List.of(PassphraseFileFormat.MCFILE1),
			PassphraseFileFormat.readingsOf(sealed));
	}

	@Test
	void aHeaderWhereNeitherReadingIsBelievable_isTriedAsWhatItsMarkerSays()
	{
		byte[] header = ByteBuffer.allocate(40).put(MCFILE1_MAGIC).put(saltWith(15, (byte)0x7f))
			.putInt(Integer.MAX_VALUE).array();

		assertEquals(List.of(PassphraseFileFormat.MCFILE1, PassphraseFileFormat.MCFILE),
			PassphraseFileFormat.readingsOf(header));
		assertEquals(Optional.of(PassphraseFileFormat.MCFILE1), PassphraseFileFormat.of(header));
	}

	@Test
	void aHeaderTooShortToCompareTheReadings_isTriedAsWhatItsMarkerSays()
	{
		assertEquals(List.of(PassphraseFileFormat.MCFILE1, PassphraseFileFormat.MCFILE),
			PassphraseFileFormat.readingsOf(MCFILE1_MAGIC));
		assertEquals(Optional.of(PassphraseFileFormat.MCFILE1),
			PassphraseFileFormat.of(MCFILE1_MAGIC));
	}

	@Test
	void aReadingAtExactlyTheBelievableCount_isStillTried()
	{
		// the MCFILE1 reading records MOST_BELIEVABLE_ITERATIONS exactly; the MCFILE reading,
		// whose last salt byte is 1, records more than 16 million
		byte[] header = ByteBuffer.allocate(40).put(MCFILE1_MAGIC).put(saltWith(15, (byte)1))
			.putInt((int)PassphraseFileFormat.MOST_BELIEVABLE_ITERATIONS).array();

		assertEquals(List.of(PassphraseFileFormat.MCFILE1),
			PassphraseFileFormat.readingsOf(header));
	}

	@Test
	void aHeaderExactlyAsLongAsItsLayout_isReadNotTakenAsTooShort()
	{
		// 27 bytes, all an MCFILE1 header has: its recorded count, 100 000 000, cannot be believed;
		// read as an MCFILE, with the last salt byte 0, the count is 100 000 000 >> 8 = 390 625
		byte[] header = ByteBuffer.allocate(PassphraseEnvelope.headerLength(MCFILE1_MAGIC))
			.put(MCFILE1_MAGIC).put(saltWith(15, (byte)0)).putInt(100_000_000).array();

		assertEquals(List.of(PassphraseFileFormat.MCFILE), PassphraseFileFormat.readingsOf(header));
	}

	private static byte[] saltWith(final int position, final byte value)
	{
		byte[] salt = new byte[PassphraseEnvelope.SALT_LENGTH];
		Arrays.fill(salt, (byte)0x55);
		salt[position] = value;
		return salt;
	}
}
