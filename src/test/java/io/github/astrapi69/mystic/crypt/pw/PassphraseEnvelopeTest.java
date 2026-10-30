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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The envelope has one job that no round trip of its own can check: opening the files that are
 * already on disk. mystic-crypt-ui 8.6 writes every master-password database and every file-crypt
 * output with its own {@code PassphraseBox}, and the whole point of moving the construction here is
 * that those files keep opening (#160) - so the first test is a file that application wrote.
 */
class PassphraseEnvelopeTest
{

	/** The magic the vault of mystic-crypt-ui uses */
	private static final byte[] VAULT_MAGIC = "MCRDB2".getBytes(StandardCharsets.US_ASCII);

	/**
	 * Written by mystic-crypt-ui's {@code PassphraseBox.encrypt(MCRDB2, plaintext, passphrase)} on
	 * 2026-10-03, against the application's develop (commit 3ed8b4ec), with the passphrase and the
	 * plaintext below. 127 bytes: 6 magic, 16 salt, 4 iterations, 101 payload
	 */
	private static final String WRITTEN_BY_THE_APPLICATION = "TUNSREIyHf+Gu4ihvTzqgWNYbjDKtw"
		+ "AJJ8CM/zNOK8pVD/l9ryz4t9LbQxVT6LH/cUI8XNBrcqM3XfTZjKbQEHThvoCi64G3HB5iQJFeNOcIlqxRkAOE"
		+ "oyFtHtQuZcb5Rvn4SztJu4XP/oYjTzqCir5pUKX9B8tx74aFLK2J+w==";

	private static final char[] PASSPHRASE = "correct horse battery staple".toCharArray();

	private static final String PLAINTEXT = "the vault of 8.6, with an umlaut: Grüße";

	@Test
	@DisplayName("a file written by mystic-crypt-ui 8.6 opens, byte for byte")
	void aFileWrittenByTheApplication_opens() throws Exception
	{
		byte[] sealed = Base64.getDecoder().decode(WRITTEN_BY_THE_APPLICATION);

		byte[] opened = PassphraseEnvelope.decrypt(VAULT_MAGIC, sealed, PASSPHRASE.clone());

		assertArrayEquals(PLAINTEXT.getBytes(StandardCharsets.UTF_8), opened,
			"the layout this class writes has to be the layout 8.6 already wrote, or every vault "
				+ "in existence stops opening");
	}

	@Test
	@DisplayName("what it writes, it reads back")
	void whatItWrites_itReadsBack() throws Exception
	{
		byte[] magic = "LTHWLT".getBytes(StandardCharsets.US_ASCII);
		byte[] plaintext = "a wallet seed".getBytes(StandardCharsets.UTF_8);

		byte[] sealed = PassphraseEnvelope.encrypt(magic, plaintext, PASSPHRASE.clone());

		assertArrayEquals(plaintext, PassphraseEnvelope.decrypt(magic, sealed, PASSPHRASE.clone()));
	}

	@Test
	@DisplayName("the same plaintext twice gives two different files, because the salt is fresh")
	void twoEncryptionsOfTheSameThing_differ() throws Exception
	{
		byte[] plaintext = "the same thing".getBytes(StandardCharsets.UTF_8);

		byte[] first = PassphraseEnvelope.encrypt(VAULT_MAGIC, plaintext, PASSPHRASE.clone());
		byte[] second = PassphraseEnvelope.encrypt(VAULT_MAGIC, plaintext, PASSPHRASE.clone());

		assertFalse(Arrays.equals(first, second),
			"a reused salt would make two files with the same passphrase comparable");
	}

	/**
	 * The test above compares whole files, and the payload's own AEAD nonce makes two files differ
	 * whatever the salt is: with the salt left all zeros it still passed (#227, the counter-run
	 * that removed {@code nextBytes(salt)}). This one looks at the salt itself, and at the
	 * ciphertext behind the header, which a fixed salt would make depend on the passphrase alone.
	 */
	@Test
	@DisplayName("the same passphrase and plaintext twice give two different salts and ciphertexts")
	void twoEncryptionsOfTheSameThing_carryDifferentSaltsAndCiphertexts() throws Exception
	{
		byte[] plaintext = "the same thing".getBytes(StandardCharsets.UTF_8);
		int saltStart = VAULT_MAGIC.length;
		int headerLength = PassphraseEnvelope.headerLength(VAULT_MAGIC);

		byte[] first = PassphraseEnvelope.encrypt(VAULT_MAGIC, plaintext, PASSPHRASE.clone());
		byte[] second = PassphraseEnvelope.encrypt(VAULT_MAGIC, plaintext, PASSPHRASE.clone());

		byte[] firstSalt = Arrays.copyOfRange(first, saltStart,
			saltStart + PassphraseEnvelope.SALT_LENGTH);
		byte[] secondSalt = Arrays.copyOfRange(second, saltStart,
			saltStart + PassphraseEnvelope.SALT_LENGTH);
		assertFalse(Arrays.equals(firstSalt, secondSalt),
			"each envelope draws its own salt; a fixed one makes the key depend on the passphrase "
				+ "alone");
		assertFalse(
			Arrays.equals(Arrays.copyOfRange(first, headerLength, first.length),
				Arrays.copyOfRange(second, headerLength, second.length)),
			"the same plaintext under the same passphrase must not seal to the same ciphertext");
	}

	/**
	 * The salt is 16 bytes in every file already on disk, so its width is fixed by those files and
	 * not by the constant: the iteration count has to sit right behind 16 bytes of salt, and the
	 * constant has to say 16
	 */
	@Test
	@DisplayName("the salt is 16 bytes wide, the width every existing file has")
	void theSaltIsSixteenBytes() throws Exception
	{
		byte[] sealed = PassphraseEnvelope.encrypt(VAULT_MAGIC,
			"x".getBytes(StandardCharsets.UTF_8), PASSPHRASE.clone());

		assertEquals(16, PassphraseEnvelope.SALT_LENGTH);
		assertEquals(PassphraseEnvelope.ITERATIONS,
			ByteBuffer.wrap(sealed, VAULT_MAGIC.length + 16, Integer.BYTES).getInt(),
			"the iteration count follows exactly 16 bytes of salt");
	}

	@Test
	@DisplayName("the header is magic, then a 16 byte salt, then the iteration count big endian")
	void theHeaderIsTheLayoutTheApplicationWrote() throws Exception
	{
		byte[] sealed = PassphraseEnvelope.encrypt(VAULT_MAGIC,
			"x".getBytes(StandardCharsets.UTF_8), PASSPHRASE.clone());

		assertArrayEquals(VAULT_MAGIC, Arrays.copyOf(sealed, VAULT_MAGIC.length));
		assertEquals(VAULT_MAGIC.length + PassphraseEnvelope.SALT_LENGTH + Integer.BYTES,
			PassphraseEnvelope.headerLength(VAULT_MAGIC));
		assertEquals(PassphraseEnvelope.ITERATIONS,
			ByteBuffer
				.wrap(sealed, VAULT_MAGIC.length + PassphraseEnvelope.SALT_LENGTH, Integer.BYTES)
				.getInt(),
			"the recorded cost is what a later reader derives with");
		assertTrue(sealed.length > PassphraseEnvelope.headerLength(VAULT_MAGIC),
			"there has to be a payload behind the header");
	}

	@Test
	@DisplayName("a file carries the cost it was written with, so a raised cost reads the old one")
	void anotherIterationCount_isReadOutOfTheFile() throws Exception
	{
		byte[] plaintext = "written when the cost was lower".getBytes(StandardCharsets.UTF_8);
		byte[] salt = new byte[PassphraseEnvelope.SALT_LENGTH];
		Arrays.fill(salt, (byte)7);
		int cheaperCost = 1000;

		byte[] sealed = PassphraseEnvelope.seal(VAULT_MAGIC, plaintext, PASSPHRASE.clone(), salt,
			cheaperCost);

		assertEquals(cheaperCost, PassphraseEnvelope.iterationsOf(VAULT_MAGIC, sealed));
		assertArrayEquals(plaintext,
			PassphraseEnvelope.decrypt(VAULT_MAGIC, sealed, PASSPHRASE.clone()));
	}

	@Test
	@DisplayName("a wrong passphrase does not open it")
	void aWrongPassphrase_doesNotOpenIt() throws Exception
	{
		byte[] sealed = PassphraseEnvelope.encrypt(VAULT_MAGIC,
			"secret".getBytes(StandardCharsets.UTF_8), PASSPHRASE.clone());

		// SecurityException, not merely some exception: it is how a caller tells "this would not
		// open" from "this is not ours at all", which is an IllegalArgumentException - the same
		// contract PassphraseCryptor has, and the one the command line's exit codes rest on
		assertThrows(SecurityException.class, () -> PassphraseEnvelope.decrypt(VAULT_MAGIC, sealed,
			"not the passphrase".toCharArray()));
	}

	/**
	 * Every header field is associated data, so changing any one of them has to fail - and each one
	 * separately, because a single case passing says nothing about the other two (#160)
	 */
	@ParameterizedTest(name = "a changed {0} does not open")
	@CsvSource({ "magic, 0", "salt, 6", "iteration count, 22" })
	@DisplayName("a tampered header does not open, field by field")
	void aTamperedHeader_doesNotOpen(final String field, final int position) throws Exception
	{
		byte[] sealed = PassphraseEnvelope.encrypt(VAULT_MAGIC,
			"secret".getBytes(StandardCharsets.UTF_8), PASSPHRASE.clone());
		sealed[position] = (byte)(sealed[position] ^ 0x01);

		Class<? extends Exception> expected = "magic".equals(field)
			? IllegalArgumentException.class
			: SecurityException.class;
		assertThrows(expected,
			() -> PassphraseEnvelope.decrypt(VAULT_MAGIC, sealed, PASSPHRASE.clone()),
			"a changed " + field + " at byte " + position + " has to be refused as "
				+ expected.getSimpleName());
	}

	/**
	 * Salt and iteration count feed the key, so changing either fails the key commitment first.
	 * What reaches the GCM tag with the right key is a changed payload - and that is the case that
	 * has to come out as the same answer, or a caller reads "altered data" as "not this format"
	 */
	@Test
	@DisplayName("an altered payload is refused as would-not-open, not as not-ours")
	void anAlteredPayload_isRefusedAsWouldNotOpen() throws Exception
	{
		byte[] sealed = PassphraseEnvelope.encrypt(VAULT_MAGIC,
			"do not tamper".getBytes(StandardCharsets.UTF_8), PASSPHRASE.clone());
		sealed[sealed.length - 1] ^= 0x01;

		SecurityException thrown = assertThrows(SecurityException.class,
			() -> PassphraseEnvelope.decrypt(VAULT_MAGIC, sealed, PASSPHRASE.clone()));

		assertTrue(thrown.getMessage().contains("passphrase is wrong or the data was altered"),
			"the message has to name both possible causes: " + thrown.getMessage());
	}

	/**
	 * The class promises that the caller owns the passphrase array: read, never modified, on
	 * success and on failure. A caller that wipes it afterwards relies on that, and so does one
	 * that still needs it for a second call - so the promise is held here, for every char[] entry
	 * point
	 */
	@Test
	@DisplayName("the passphrase array is the caller's: read, never modified, even on failure")
	void thePassphraseArray_isNeverModified() throws Exception
	{
		char[] passphrase = PASSPHRASE.clone();
		byte[] salt = new byte[PassphraseEnvelope.SALT_LENGTH];

		byte[] sealed = PassphraseEnvelope.encrypt(VAULT_MAGIC,
			"x".getBytes(StandardCharsets.UTF_8), passphrase);
		assertArrayEquals(PASSPHRASE, passphrase, "encrypt must leave the array as it was");

		PassphraseEnvelope.decrypt(VAULT_MAGIC, sealed, passphrase);
		assertArrayEquals(PASSPHRASE, passphrase, "decrypt must leave the array as it was");

		PassphraseEnvelope.deriveKey(passphrase, salt, 1000);
		assertArrayEquals(PASSPHRASE, passphrase, "deriveKey must leave the array as it was");

		sealed[sealed.length - 1] ^= 0x01;
		assertThrows(SecurityException.class,
			() -> PassphraseEnvelope.decrypt(VAULT_MAGIC, sealed, passphrase));
		assertArrayEquals(PASSPHRASE, passphrase,
			"a failed decrypt must leave the array as it was, too");
	}

	/**
	 * What a caller has to handle is the JDK's GeneralSecurityException and nothing wider: the two
	 * answers it acts on are runtime exceptions (#182). Compiling this method is the first half of
	 * the assertion - it declares nothing but GeneralSecurityException and calls every entry point
	 */
	@Test
	@DisplayName("every entry point compiles in a method that declares only GeneralSecurityException")
	void everyEntryPoint_needsNothingWiderThanGeneralSecurityException()
		throws GeneralSecurityException
	{
		byte[] plaintext = "x".getBytes(StandardCharsets.UTF_8);
		byte[] fromCharacters = PassphraseEnvelope.encrypt(VAULT_MAGIC, plaintext,
			PASSPHRASE.clone());
		byte[] fromString = PassphraseEnvelope.encrypt(VAULT_MAGIC, plaintext,
			new String(PASSPHRASE));

		assertArrayEquals(plaintext,
			PassphraseEnvelope.decrypt(VAULT_MAGIC, fromCharacters, PASSPHRASE.clone()));
		assertArrayEquals(plaintext,
			PassphraseEnvelope.decrypt(VAULT_MAGIC, fromString, new String(PASSPHRASE)));
		assertArrayEquals(
			PassphraseEnvelope.deriveKey(PASSPHRASE.clone(), new byte[16], 1000).getEncoded(),
			PassphraseEnvelope.deriveKey(new String(PASSPHRASE), new byte[16], 1000).getEncoded());
	}

	/**
	 * The second half, for every public method there is and every one added later: nothing it
	 * declares is wider than GeneralSecurityException (#182)
	 */
	@Test
	@DisplayName("no public method declares an exception wider than GeneralSecurityException")
	void noPublicMethod_declaresAnythingWider()
	{
		List<String> wider = new ArrayList<>();
		for (Method method : PassphraseEnvelope.class.getDeclaredMethods())
		{
			if (!Modifier.isPublic(method.getModifiers()))
			{
				continue;
			}
			for (Class<?> declared : method.getExceptionTypes())
			{
				if (!GeneralSecurityException.class.isAssignableFrom(declared)
					&& !RuntimeException.class.isAssignableFrom(declared))
				{
					wider.add(method.getName() + " declares " + declared.getSimpleName());
				}
			}
		}

		assertEquals(List.of(), wider);
	}

	/**
	 * What the cipher throws reaches the caller as this class declares it: the JDK's security
	 * exception and runtime exceptions unchanged, the same instance (#182)
	 */
	@ParameterizedTest(name = "{0} passes through unchanged")
	@MethodSource("whatPassesThrough")
	@DisplayName("a security failure or a runtime exception from the cipher passes through as it is")
	void aSecurityOrRuntimeFailure_passesThroughUnchanged(final String what, final Exception thrown)
	{
		Exception caught = assertThrows(Exception.class, () -> PassphraseEnvelope.runCipher(() -> {
			throw thrown;
		}));

		assertSame(thrown, caught, what + " must reach the caller as it was thrown");
	}

	static Stream<Arguments> whatPassesThrough()
	{
		return Stream.of(
			Arguments.of("a GeneralSecurityException", new GeneralSecurityException("no provider")),
			Arguments.of("a SecurityException", new SecurityException("would not open")));
	}

	@Test
	@DisplayName("any other checked exception from the cipher becomes a GeneralSecurityException carrying it")
	void anyOtherCheckedFailure_becomesAGeneralSecurityException()
	{
		IOException thrown = new IOException("not a security failure");

		GeneralSecurityException caught = assertThrows(GeneralSecurityException.class,
			() -> PassphraseEnvelope.runCipher(() -> {
				throw thrown;
			}));

		assertSame(thrown, caught.getCause(), "the original failure travels as the cause");
		assertTrue(caught.getMessage().contains("not a security failure"), caught.getMessage());
	}

	@Test
	@DisplayName("content without the marker is refused, and the message says so")
	void contentWithoutTheMarker_isRefused()
	{
		byte[] notThisFormat = "KDBX and then some".getBytes(StandardCharsets.UTF_8);

		IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
			() -> PassphraseEnvelope.decrypt(VAULT_MAGIC, notThisFormat, PASSPHRASE.clone()));

		assertTrue(thrown.getMessage().contains("marker"),
			"a file of another format has to be named as one, not reported as a wrong passphrase");
	}

	@Test
	@DisplayName("a marker with nothing behind it is refused as truncated")
	void aTruncatedFile_isRefused()
	{
		byte[] headerOnly = new byte[PassphraseEnvelope.headerLength(VAULT_MAGIC)];
		System.arraycopy(VAULT_MAGIC, 0, headerOnly, 0, VAULT_MAGIC.length);

		IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
			() -> PassphraseEnvelope.decrypt(VAULT_MAGIC, headerOnly, PASSPHRASE.clone()));

		assertTrue(thrown.getMessage().contains("truncated"));
	}

	/**
	 * The reserved marker is the whole reason the general form can do without a version byte: a
	 * file starting with MCRYPT is a {@link PassphraseCryptor} file, which has one, and nothing
	 * else - otherwise byte 6 is a version in one layout and the first salt byte in the other
	 * (#160)
	 */
	@Test
	@DisplayName("the marker of the released layout is refused as a caller's magic")
	void theReservedMarker_isRefused()
	{
		IllegalArgumentException thrown = assertThrows(IllegalArgumentException.class,
			() -> PassphraseEnvelope.encrypt(PassphraseCryptor.MAGIC,
				"x".getBytes(StandardCharsets.UTF_8), PASSPHRASE.clone()));

		assertTrue(thrown.getMessage().contains("MCRYPT"),
			"the message has to name the marker that is taken, or the caller cannot pick another");
		// content that does start with the marker: zeros alone would be refused as not carrying
		// it, and that refusal has the same type, which let the missing check pass unnoticed (#227)
		byte[] startsWithTheMarker = Arrays.copyOf(PassphraseCryptor.MAGIC, 64);
		IllegalArgumentException onReading = assertThrows(IllegalArgumentException.class,
			() -> PassphraseEnvelope.decrypt(PassphraseCryptor.MAGIC, startsWithTheMarker,
				PASSPHRASE.clone()),
			"and reading under that marker is the same mistake as writing under it");
		assertTrue(onReading.getMessage().contains("belongs to PassphraseCryptor"),
			"the read has to be refused for the marker, not for anything after it, but said: "
				+ onReading.getMessage());
	}

	@Test
	@DisplayName("asking whether content carries a marker answers for null and for short content")
	void hasMagic_answersForEveryShapeOfContent() throws Exception
	{
		byte[] sealed = PassphraseEnvelope.encrypt(VAULT_MAGIC,
			"x".getBytes(StandardCharsets.UTF_8), PASSPHRASE.clone());

		assertTrue(PassphraseEnvelope.hasMagic(sealed, VAULT_MAGIC));
		assertTrue(PassphraseEnvelope.hasMagic(VAULT_MAGIC.clone(), VAULT_MAGIC),
			"content exactly as long as the marker carries it");
		assertFalse(PassphraseEnvelope.hasMagic(null, VAULT_MAGIC), "null is not a file");
		assertFalse(PassphraseEnvelope.hasMagic(new byte[] { 'M', 'C' }, VAULT_MAGIC),
			"content shorter than the marker cannot carry it");
		assertFalse(PassphraseEnvelope.hasMagic(
			"MCRDB1xxxxxxxxxxxxxxxxxxxxxxxxxx".getBytes(StandardCharsets.US_ASCII), VAULT_MAGIC),
			"another marker is not this one");
	}

	@Test
	@DisplayName("the passphrase can be handed over as a String, and that reads the same file")
	void theStringOverload_readsWhatTheCharacterOverloadWrote() throws Exception
	{
		String passphrase = new String(PASSPHRASE);
		byte[] plaintext = "both overloads, one construction".getBytes(StandardCharsets.UTF_8);

		byte[] sealed = PassphraseEnvelope.encrypt(VAULT_MAGIC, plaintext, passphrase);

		assertArrayEquals(plaintext,
			PassphraseEnvelope.decrypt(VAULT_MAGIC, sealed, PASSPHRASE.clone()));
		assertArrayEquals(plaintext, PassphraseEnvelope.decrypt(VAULT_MAGIC,
			PassphraseEnvelope.encrypt(VAULT_MAGIC, plaintext, PASSPHRASE.clone()), passphrase));
	}

	@Test
	@DisplayName("the derived key is the one the cost and the salt say it is")
	void theDerivedKey_followsSaltAndCost() throws Exception
	{
		byte[] salt = new byte[PassphraseEnvelope.SALT_LENGTH];
		Arrays.fill(salt, (byte)3);

		byte[] fromCharacters = PassphraseEnvelope.deriveKey(PASSPHRASE.clone(), salt, 1000)
			.getEncoded();

		assertArrayEquals(fromCharacters,
			PassphraseEnvelope.deriveKey(new String(PASSPHRASE), salt, 1000).getEncoded(),
			"the String overload must not derive a different key than the character one");
		assertEquals(PassphraseEnvelope.KEY_LENGTH_BITS / 8, fromCharacters.length);
		assertFalse(
			Arrays.equals(fromCharacters,
				PassphraseEnvelope.deriveKey(PASSPHRASE.clone(), salt, 2000).getEncoded()),
			"a different cost is a different key");
	}
}
