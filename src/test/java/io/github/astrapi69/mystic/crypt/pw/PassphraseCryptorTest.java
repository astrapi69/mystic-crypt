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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Unit tests for {@link PassphraseCryptor}, the passphrase-based authenticated encryption behind
 * the {@code encrypt} and {@code decrypt} commands.
 */
class PassphraseCryptorTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	private static char[] passphrase(String value)
	{
		return value.toCharArray();
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "a", "the quick brown fox", "unicode: Ärger, Straße, 漢字" })
	void whatWasEncryptedComesBackByteForByte(String plainText) throws Exception
	{
		byte[] plain = plainText.getBytes(StandardCharsets.UTF_8);

		byte[] encrypted = PassphraseCryptor.encrypt(passphrase("correct horse"), plain);
		byte[] decrypted = PassphraseCryptor.decrypt(passphrase("correct horse"), encrypted);

		assertArrayEquals(plain, decrypted);
	}

	@Test
	void aWrongPassphraseFailsLoudlyInsteadOfReturningRubbish() throws Exception
	{
		byte[] encrypted = PassphraseCryptor.encrypt(passphrase("right one"),
			"secret".getBytes(StandardCharsets.UTF_8));

		Exception rejected = assertThrows(Exception.class,
			() -> PassphraseCryptor.decrypt(passphrase("wrong one"), encrypted));

		assertFalse(rejected.getMessage() == null || rejected.getMessage().isBlank(),
			"the failure must name a reason, but the message was: '" + rejected.getMessage() + "'");
	}

	@Test
	void alteringOneByteOfTheCiphertextIsDetected() throws Exception
	{
		byte[] encrypted = PassphraseCryptor.encrypt(passphrase("pass"),
			"tamper with me".getBytes(StandardCharsets.UTF_8));
		// flip a bit in the middle, past the header and inside the ciphertext
		byte[] tampered = encrypted.clone();
		int middle = PassphraseCryptor.HEADER_LENGTH
			+ (tampered.length - PassphraseCryptor.HEADER_LENGTH) / 2;
		tampered[middle] ^= 0x01;

		assertThrows(Exception.class,
			() -> PassphraseCryptor.decrypt(passphrase("pass"), tampered));
	}

	@Test
	void theOutputStartsWithTheFormatMarkerAndItsVersion()
	{
		byte[] encrypted = PassphraseCryptor.encrypt(passphrase("pass"),
			"marked".getBytes(StandardCharsets.UTF_8));

		byte[] marker = Arrays.copyOf(encrypted, PassphraseCryptor.MAGIC.length);
		assertArrayEquals(PassphraseCryptor.MAGIC, marker,
			"the output must be recognisable by its leading marker");
		assertEquals(PassphraseCryptor.FORMAT_VERSION, encrypted[PassphraseCryptor.MAGIC.length],
			"the byte after the marker must be the format version, so the format can be changed "
				+ "later without guessing");
		assertTrue(PassphraseCryptor.isEncrypted(encrypted),
			"a freshly encrypted blob must be recognised as one");
	}

	@Test
	void encryptingTheSameInputTwiceYieldsDifferentOutput()
	{
		byte[] plain = "same input".getBytes(StandardCharsets.UTF_8);

		byte[] first = PassphraseCryptor.encrypt(passphrase("pass"), plain);
		byte[] second = PassphraseCryptor.encrypt(passphrase("pass"), plain);

		assertFalse(Arrays.equals(first, second),
			"a fresh salt and nonce per call must make two encryptions of the same input differ");
	}

	@Test
	void inputThatIsNotOfThisFormatIsRejectedByName()
	{
		byte[] foreign = "this is a plain text file, not an encrypted one"
			.getBytes(StandardCharsets.UTF_8);
		assertFalse(PassphraseCryptor.isEncrypted(foreign));

		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> PassphraseCryptor.decrypt(passphrase("pass"), foreign));
		assertTrue(rejected.getMessage().contains("mystic-crypt"),
			"the message must say what the input was expected to be, but was: '"
				+ rejected.getMessage() + "'");
	}

	@Test
	void anInputTooShortToHoldAHeaderIsRejectedRatherThanIndexed()
	{
		byte[] tooShort = { 'M', 'C', 'R' };
		assertFalse(PassphraseCryptor.isEncrypted(tooShort));
		assertThrows(IllegalArgumentException.class,
			() -> PassphraseCryptor.decrypt(passphrase("pass"), tooShort));
	}

	@Test
	void theIterationCountIsAtLeastTheOwaspFloorAndTravelsWithTheOutput()
	{
		assertTrue(PassphraseCryptor.DEFAULT_ITERATIONS >= 600_000,
			"PBKDF2-HMAC-SHA256 below 600000 iterations is under the OWASP guidance");

		byte[] encrypted = PassphraseCryptor.encrypt(passphrase("pass"),
			"iterations".getBytes(StandardCharsets.UTF_8));

		assertEquals(PassphraseCryptor.DEFAULT_ITERATIONS,
			PassphraseCryptor.iterationsOf(encrypted),
			"the iteration count must be readable from the output, so a later default change can "
				+ "still decrypt what an older default produced");
	}

	@Test
	void nothingAndTheRightMarkerWithAForeignVersionAreBothRefused()
	{
		assertFalse(PassphraseCryptor.isEncrypted(null), "no input is not encrypted input");

		byte[] futureVersion = PassphraseCryptor.encrypt(passphrase("pass"),
			"from a later format".getBytes(StandardCharsets.UTF_8));
		futureVersion[PassphraseCryptor.MAGIC.length] = PassphraseCryptor.FORMAT_VERSION + 1;

		assertFalse(PassphraseCryptor.isEncrypted(futureVersion),
			"a version this build does not know must not be treated as readable");
		assertThrows(IllegalArgumentException.class,
			() -> PassphraseCryptor.decrypt(passphrase("pass"), futureVersion));
	}

	@Test
	void anInputThatCannotBeSealedIsReportedAsSuchAndStillClearsThePassphrase()
	{
		char[] toEncrypt = passphrase("wipe me too");

		IllegalStateException failed = assertThrows(IllegalStateException.class,
			() -> PassphraseCryptor.encrypt(toEncrypt, null));

		assertTrue(failed.getMessage().contains("could not encrypt"),
			"the message must say what failed, but was: '" + failed.getMessage() + "'");
		assertArrayEquals(new char[toEncrypt.length], toEncrypt,
			"the passphrase must be cleared on the failure path as well");
	}

	@Test
	void decryptClearsThePassphraseOnBothPaths()
	{
		byte[] encrypted = PassphraseCryptor.encrypt(passphrase("right"),
			"payload".getBytes(StandardCharsets.UTF_8));

		char[] onSuccess = passphrase("right");
		PassphraseCryptor.decrypt(onSuccess, encrypted);
		assertArrayEquals(new char[onSuccess.length], onSuccess,
			"decrypt must zero the passphrase after a successful open");

		char[] onFailure = passphrase("wrong");
		assertThrows(SecurityException.class,
			() -> PassphraseCryptor.decrypt(onFailure, encrypted));
		assertArrayEquals(new char[onFailure.length], onFailure,
			"and after a failed one, which is when it matters most");
	}

	/**
	 * The iteration count can only be read out of this format, and says so when asked otherwise.
	 */
	@Test
	void theIterationCountCannotBeReadFromSomethingThatIsNotThisFormat()
	{
		byte[] foreign = "not encrypted by this tool".getBytes(StandardCharsets.UTF_8);

		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> PassphraseCryptor.iterationsOf(foreign));

		assertTrue(rejected.getMessage().contains("marker"),
			"the message was: '" + rejected.getMessage() + "'");
	}

	/**
	 * The header length is the boundary between "too short to even look at" and "long enough to
	 * check", so both sides of it are pinned rather than only one.
	 */
	@Test
	void oneByteShortOfAHeaderIsNotEncryptedAndExactlyAHeaderIsLookedAt()
	{
		byte[] oneShort = new byte[PassphraseCryptor.HEADER_LENGTH - 1];
		System.arraycopy(PassphraseCryptor.MAGIC, 0, oneShort, 0, PassphraseCryptor.MAGIC.length);
		oneShort[PassphraseCryptor.MAGIC.length] = PassphraseCryptor.FORMAT_VERSION;

		byte[] exactly = new byte[PassphraseCryptor.HEADER_LENGTH];
		System.arraycopy(PassphraseCryptor.MAGIC, 0, exactly, 0, PassphraseCryptor.MAGIC.length);
		exactly[PassphraseCryptor.MAGIC.length] = PassphraseCryptor.FORMAT_VERSION;

		assertFalse(PassphraseCryptor.isEncrypted(oneShort),
			"one byte short of a header cannot carry one");
		assertTrue(PassphraseCryptor.isEncrypted(exactly),
			"exactly a header is a header, even with no payload behind it");
	}

	@Test
	void thePassphraseArrayIsClearedSoItCannotLingerInMemory()
	{
		char[] toEncrypt = passphrase("wipe me");
		PassphraseCryptor.encrypt(toEncrypt, "x".getBytes(StandardCharsets.UTF_8));

		assertArrayEquals(new char[toEncrypt.length], toEncrypt,
			"encrypt must zero the passphrase it was given, as the rest of this package does");
	}
}
