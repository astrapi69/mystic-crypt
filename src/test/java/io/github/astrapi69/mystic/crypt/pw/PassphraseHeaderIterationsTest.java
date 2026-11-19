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
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.stream.Stream;

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.mystic.crypt.aead.KeyCommittingAeadEncryptor;

/**
 * The iteration count a header records is checked against
 * {@link PassphraseEnvelope#MAXIMUM_ITERATIONS} by every reader and by {@code seal}, before the
 * first derivation. A refused count costs no derivation time: a derivation at the bound takes about
 * 0.3 s, a refusal well under 0.1 s. The bound itself and today's 600 000 open a valid file.
 */
class PassphraseHeaderIterationsTest
{

	private static final char[] PASSPHRASE = "a passphrase for the header".toCharArray();

	private static final byte[] PLAINTEXT = "what was sealed".getBytes(StandardCharsets.UTF_8);

	private static final byte[] MCFILE_MAGIC = "MCFILE".getBytes(StandardCharsets.US_ASCII);

	private static final byte[] MCFILE1_MAGIC = "MCFILE1".getBytes(StandardCharsets.US_ASCII);

	private static final int BOUND = PassphraseEnvelope.MAXIMUM_ITERATIONS;

	/** A refusal that took this long, in milliseconds, spent time on a derivation */
	private static final long REFUSAL_MILLISECONDS_AT_MOST = 100;

	/** One way into a derivation, fed a header that records the given count */
	@FunctionalInterface
	interface Entrance
	{
		Object enter(int iterations) throws Exception;
	}

	private record Named(String name, Entrance entrance) {
		@Override
		public String toString()
		{
			return name;
		}
	}

	private static byte[] salt()
	{
		byte[] salt = new byte[PassphraseEnvelope.SALT_LENGTH];
		Arrays.fill(salt, (byte)9);
		return salt;
	}

	private static byte[] envelopeHeaderOnly(final byte[] magic, final int iterations)
	{
		return ByteBuffer.allocate(PassphraseEnvelope.headerLength(magic) + 32).put(magic)
			.put(salt()).putInt(iterations).array();
	}

	private static byte[] cryptorHeaderOnly(final int iterations)
	{
		return ByteBuffer.allocate(PassphraseCryptor.HEADER_LENGTH + 32)
			.put(PassphraseCryptor.MAGIC).put(PassphraseCryptor.FORMAT_VERSION).putInt(iterations)
			.put(salt()).array();
	}

	private static byte[] cryptorContent(final int iterations) throws Exception
	{
		byte[] keyBytes = Pbkdf2Support.deriveKey(PASSPHRASE.clone(), salt(), iterations, 256);
		byte[] payload = new KeyCommittingAeadEncryptor(new SecretKeySpec(keyBytes, "AES"))
			.encrypt(PLAINTEXT);
		return ByteBuffer.allocate(PassphraseCryptor.HEADER_LENGTH + payload.length)
			.put(PassphraseCryptor.MAGIC).put(PassphraseCryptor.FORMAT_VERSION).putInt(iterations)
			.put(salt()).put(payload).array();
	}

	private static Stream<Named> entrances()
	{
		return Stream.of(
			new Named("envelope reader",
				iterations -> PassphraseEnvelope.decrypt(MCFILE1_MAGIC,
					envelopeHeaderOnly(MCFILE1_MAGIC, iterations), PASSPHRASE.clone())),
			new Named("envelope reader, String passphrase",
				iterations -> PassphraseEnvelope.decrypt(MCFILE1_MAGIC,
					envelopeHeaderOnly(MCFILE1_MAGIC, iterations), new String(PASSPHRASE))),
			new Named("cryptor reader",
				iterations -> PassphraseCryptor.decrypt(PASSPHRASE.clone(),
					cryptorHeaderOnly(iterations))),
			new Named("file reader, MCFILE1",
				iterations -> PassphraseFileFormat
					.open(envelopeHeaderOnly(MCFILE1_MAGIC, iterations), PASSPHRASE.clone())),
			new Named("file reader, MCFILE",
				iterations -> PassphraseFileFormat
					.open(envelopeHeaderOnly(MCFILE_MAGIC, iterations), PASSPHRASE.clone())),
			new Named("file reader, MCRYPT",
				iterations -> PassphraseFileFormat.open(cryptorHeaderOnly(iterations),
					PASSPHRASE.clone())),
			new Named("seal", iterations -> PassphraseEnvelope.seal(MCFILE1_MAGIC, PLAINTEXT,
				PASSPHRASE.clone(), salt(), iterations)));
	}

	private static Stream<Arguments> entrancesAndRefusedCounts()
	{
		return entrances()
			.flatMap(entrance -> Stream.of(Integer.MAX_VALUE, 0, -1, Integer.MIN_VALUE, BOUND + 1)
				.map(count -> Arguments.of(entrance, count)));
	}

	@ParameterizedTest(name = "{0} refuses {1} iterations")
	@MethodSource("entrancesAndRefusedCounts")
	void aCountOutsideOneToTheBound_isRefusedBeforeTheFirstDerivation(final Named entrance,
		final int iterations) throws Exception
	{
		// the first call pays for class loading, which is no derivation either
		assertThrows(IllegalArgumentException.class, () -> entrance.entrance().enter(0));

		long start = System.nanoTime();
		IllegalArgumentException refusal = assertTimeoutPreemptively(Duration.ofSeconds(10),
			() -> assertThrows(IllegalArgumentException.class,
				() -> entrance.entrance().enter(iterations)));
		long milliseconds = (System.nanoTime() - start) / 1_000_000;

		assertTrue(milliseconds < REFUSAL_MILLISECONDS_AT_MOST,
			entrance + " took " + milliseconds + " ms to refuse " + iterations);
		assertTrue(refusal.getMessage().contains(String.valueOf(BOUND)),
			"the message names the bound: " + refusal.getMessage());
	}

	@Test
	void theBound_isTwoMillion()
	{
		assertEquals(2_000_000, PassphraseEnvelope.MAXIMUM_ITERATIONS);
	}

	@ParameterizedTest(name = "a file of {0} iterations opens")
	@MethodSource("acceptedCounts")
	void theLowestCountTheBoundAndTodaysCount_openAValidFile(final int iterations) throws Exception
	{
		byte[] envelope = PassphraseEnvelope.seal(MCFILE1_MAGIC, PLAINTEXT, PASSPHRASE.clone(),
			salt(), iterations);
		byte[] cryptor = cryptorContent(iterations);

		assertEquals(iterations, PassphraseEnvelope.iterationsOf(MCFILE1_MAGIC, envelope));
		assertArrayEquals(PLAINTEXT,
			PassphraseEnvelope.decrypt(MCFILE1_MAGIC, envelope, PASSPHRASE.clone()));
		assertArrayEquals(PLAINTEXT,
			PassphraseEnvelope.decrypt(MCFILE1_MAGIC, envelope, new String(PASSPHRASE)));
		assertArrayEquals(PLAINTEXT, PassphraseFileFormat.open(envelope, PASSPHRASE.clone()));
		byte[] mcfile = PassphraseEnvelope.seal(MCFILE_MAGIC, PLAINTEXT, PASSPHRASE.clone(), salt(),
			iterations);
		assertArrayEquals(PLAINTEXT, PassphraseFileFormat.open(mcfile, PASSPHRASE.clone()));
		assertArrayEquals(PLAINTEXT, PassphraseCryptor.decrypt(PASSPHRASE.clone(), cryptor));
		assertArrayEquals(PLAINTEXT,
			PassphraseFileFormat.open(cryptorContent(iterations), PASSPHRASE.clone()));
	}

	private static Stream<Integer> acceptedCounts()
	{
		return Stream.of(1, BOUND, 600_000);
	}

	@Test
	void theHeaderParsing_stillReadsTheLargestCountAsItIs()
	{
		assertEquals(Integer.MAX_VALUE, PassphraseEnvelope.iterationsOf(MCFILE1_MAGIC,
			envelopeHeaderOnly(MCFILE1_MAGIC, Integer.MAX_VALUE)));
		assertEquals(Integer.MAX_VALUE,
			PassphraseCryptor.iterationsOf(cryptorHeaderOnly(Integer.MAX_VALUE)));
	}
}
