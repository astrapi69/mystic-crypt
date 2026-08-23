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
package io.github.astrapi69.mystic.crypt.sha;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.IntConsumer;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Mutation-focused tests for the hasher classes: boundary conditions that must be
 * <em>accepted</em>, secure-wipe of caller supplied password arrays, random-salt behaviour and the
 * delegating hash overloads. These complement {@link HasherArgumentValidationTest} which only
 * covers the reject paths.
 */
class HasherBoundaryAndWipeTest
{

	private static final byte[] DATA = "the quick brown fox".getBytes(StandardCharsets.UTF_8);

	private static final String LOG_ROUNDS_REJECTION = "Log rounds must be between "
		+ BcryptHasher.MIN_LOG_ROUNDS + " and " + BcryptHasher.MAX_LOG_ROUNDS;

	/**
	 * The grace period the probe thread of {@link #failureOf(Runnable)} is given. Only a call that
	 * is rejected by an argument check finishes at all within it, and such a rejection takes
	 * microseconds, so the value only has to be far above any scheduling jitter.
	 */
	private static final long PROBE_GRACE_MILLIS = 2_000L;

	private static char[] pw()
	{
		return "correct horse battery staple".toCharArray();
	}

	/**
	 * A password that passes every argument check of {@link BcryptHasher} but that the underlying
	 * Bouncy Castle implementation refuses immediately: a truncated UTF-16 surrogate pair can not
	 * be encoded to UTF-8. It is the lever that makes the {@code MAX_LOG_ROUNDS} boundary
	 * observable - actually hashing with a cost factor of 2^31 would run for about a day.
	 *
	 * @return the password
	 */
	private static char[] unencodablePassword()
	{
		return new char[] { 'a', '\uD800' };
	}

	/**
	 * Runs the given call on a daemon thread and answers the throwable it failed with, or
	 * {@code null} if it had not finished within {@link #PROBE_GRACE_MILLIS}. A call that is
	 * rejected by an argument check fails right away, so the grace period is only ever waited out
	 * when the call got past every check and started to do real work - which is exactly the outcome
	 * the boundary tests want to distinguish, and the reason the probe can not simply be called on
	 * the test thread.
	 *
	 * @param call
	 *            the call to run
	 * @return the throwable the call failed with, or null if it was still running
	 * @throws InterruptedException
	 *             if the test thread is interrupted while waiting
	 */
	private static Throwable failureOf(final Runnable call) throws InterruptedException
	{
		AtomicReference<Throwable> failure = new AtomicReference<>();
		Thread worker = new Thread(() -> {
			try
			{
				call.run();
			}
			catch (Throwable thrown)
			{
				failure.set(thrown);
			}
		}, "bcrypt-log-rounds-probe");
		worker.setDaemon(true);
		worker.setPriority(Thread.MIN_PRIORITY);
		worker.start();
		worker.join(PROBE_GRACE_MILLIS);
		return failure.get();
	}

	private static boolean allZero(char[] array)
	{
		for (char c : array)
		{
			if (c != '\0')
			{
				return false;
			}
		}
		return true;
	}

	// ----- BCrypt -----------------------------------------------------------

	@Test
	void bcryptAcceptsMinimumLogRounds()
	{
		// kills the "< MIN_LOG_ROUNDS" boundary mutant: MIN itself must be accepted
		String hash = BcryptHasher.hash(pw(), BcryptHasher.MIN_LOG_ROUNDS);
		assertNotNull(hash);
		assertEquals(BcryptHasher.MIN_LOG_ROUNDS, BcryptHasher.getLogRounds(hash));

		byte[] salt = new byte[16];
		String saltedHash = BcryptHasher.hashWithSalt(pw(), salt, BcryptHasher.MIN_LOG_ROUNDS);
		assertNotNull(saltedHash);
		assertEquals(BcryptHasher.MIN_LOG_ROUNDS, BcryptHasher.getLogRounds(saltedHash));
	}

	/**
	 * A {@link BcryptHasher} entry point that takes the log rounds, so that both hashing overloads
	 * can be driven through the very same boundary assertions
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param call
	 *            the call under test, parameterised by the log rounds
	 */
	record BcryptLogRoundsCase(String description, IntConsumer call) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static Stream<BcryptLogRoundsCase> bcryptLogRoundsCases()
	{
		return Stream.of(
			new BcryptLogRoundsCase("hash",
				logRounds -> BcryptHasher.hash(unencodablePassword(), logRounds)),
			new BcryptLogRoundsCase("hash with salt", logRounds -> BcryptHasher
				.hashWithSalt(unencodablePassword(), new byte[16], logRounds)));
	}

	/**
	 * Guards the upper end of the accepted log rounds range of {@link BcryptHasher}: log rounds of
	 * exactly {@code MAX_LOG_ROUNDS} must be <em>accepted</em> and only one more must be rejected.
	 * Without the positive half, changing {@code logRounds > MAX_LOG_ROUNDS} into
	 * {@code logRounds >= MAX_LOG_ROUNDS} would go unnoticed and silently narrow the supported cost
	 * range, and the existing {@code MAX_LOG_ROUNDS + 1} case can not see that - it is rejected
	 * either way.
	 * <p>
	 * The accepted call can not be run to completion: a cost factor of 2^31 keeps BCrypt busy for
	 * roughly a day. It is therefore driven with a password that Bouncy Castle refuses to encode,
	 * so that the call fails immediately once it is past our own checks - whatever comes back, it
	 * must not be our log rounds rejection.
	 *
	 * @param testCase
	 *            the test case
	 * @throws InterruptedException
	 *             if the test thread is interrupted while waiting for the probe
	 */
	@ParameterizedTest
	@MethodSource("bcryptLogRoundsCases")
	void bcryptAcceptsMaximumLogRoundsAndRejectsOneMore(final BcryptLogRoundsCase testCase)
		throws InterruptedException
	{
		Throwable failure = failureOf(() -> testCase.call().accept(BcryptHasher.MAX_LOG_ROUNDS));

		assertFalse(
			failure instanceof IllegalArgumentException
				&& LOG_ROUNDS_REJECTION.equals(failure.getMessage()),
			() -> "log rounds of exactly " + BcryptHasher.MAX_LOG_ROUNDS
				+ " must be accepted, but the call was rejected with " + failure);

		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> testCase.call().accept(BcryptHasher.MAX_LOG_ROUNDS + 1));
		assertEquals(LOG_ROUNDS_REJECTION, rejected.getMessage());
	}

	@Test
	void bcryptHashUsesAFreshRandomSaltEveryTime()
	{
		// kills the removed SecureRandom.nextBytes(salt) call: without it the salt is all
		// zero and two hashes of the same password would be identical
		String first = BcryptHasher.hash(pw(), BcryptHasher.MIN_LOG_ROUNDS);
		String second = BcryptHasher.hash(pw(), BcryptHasher.MIN_LOG_ROUNDS);
		assertNotEquals(first, second);
	}

	@Test
	void bcryptHashWithSaltWipesThePassword()
	{
		// kills the removed Arrays.fill(password, '\0') call in hashWithSalt
		char[] password = pw();
		BcryptHasher.hashWithSalt(password, new byte[16], BcryptHasher.MIN_LOG_ROUNDS);
		assertTrue(allZero(password), "password array must be wiped after hashWithSalt");
	}

	@Test
	void bcryptVerifyWipesThePasswordAndReturnsCorrectResult()
	{
		// kills the removed Arrays.fill(password, '\0') call in verify
		String hash = BcryptHasher.hash(pw(), BcryptHasher.MIN_LOG_ROUNDS);
		char[] password = pw();
		assertTrue(BcryptHasher.verify(password, hash));
		assertTrue(allZero(password), "password array must be wiped after verify");

		char[] wrong = "wrong password".toCharArray();
		assertFalse(BcryptHasher.verify(wrong, hash));
	}

	// ----- SCrypt -----------------------------------------------------------

	@Test
	void scryptHashRejectsNonPowerOfTwoNParameter()
	{
		// kills the removed validateParameters call in hash and the "return true" mutant of
		// isPowerOfTwo: N = 3 is >= MIN_N but not a power of two and must be rejected with our
		// specific message
		IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
			() -> ScryptHasher.hash(pw(), 3, ScryptHasher.MIN_R, ScryptHasher.MIN_P));
		assertEquals("N must be a power of 2 and at least " + ScryptHasher.MIN_N, ex.getMessage());
	}

	@Test
	void scryptVerifyRejectsNonPowerOfTwoNParameter()
	{
		// kills the removed validateParameters call in verify
		IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
			() -> ScryptHasher.verify(pw(), new byte[ScryptHasher.SALT_LENGTH], new byte[32], 3,
				ScryptHasher.MIN_R, ScryptHasher.MIN_P));
		assertEquals("N must be a power of 2 and at least " + ScryptHasher.MIN_N, ex.getMessage());
	}

	/**
	 * Guards the {@code N} parameter guard of {@code ScryptHasher.validateParameters}: the smallest
	 * accepted value is {@code MIN_N}, and every value below it - zero and negative ones included -
	 * is rejected with the very same message. The zero case also pins down why the {@code n > 0}
	 * boundary inside {@code isPowerOfTwo} can not be observed from the outside: zero is the only
	 * input for which that comparison would change the answer, and the caller combines it as
	 * {@code !isPowerOfTwo(n) || n < MIN_N}, so with {@code MIN_N} of 2 both halves reject zero.
	 */
	@Test
	void scryptAcceptsTheMinimumNParameterAndRejectsEverythingBelow()
	{
		String expectedMessage = "N must be a power of 2 and at least " + ScryptHasher.MIN_N;

		assertNotNull(
			ScryptHasher.hash(pw(), ScryptHasher.MIN_N, ScryptHasher.MIN_R, ScryptHasher.MIN_P));

		IllegalArgumentException zero = assertThrows(IllegalArgumentException.class,
			() -> ScryptHasher.hash(pw(), 0, ScryptHasher.MIN_R, ScryptHasher.MIN_P));
		assertEquals(expectedMessage, zero.getMessage());

		IllegalArgumentException negative = assertThrows(IllegalArgumentException.class,
			() -> ScryptHasher.hash(pw(), -2, ScryptHasher.MIN_R, ScryptHasher.MIN_P));
		assertEquals(expectedMessage, negative.getMessage());

		IllegalArgumentException one = assertThrows(IllegalArgumentException.class,
			() -> ScryptHasher.hash(pw(), ScryptHasher.MIN_N - 1, ScryptHasher.MIN_R,
				ScryptHasher.MIN_P));
		assertEquals(expectedMessage, one.getMessage());
	}

	@Test
	void scryptHashUsesAFreshRandomSaltEveryTime()
	{
		// kills the removed SecureRandom.nextBytes(salt) call in generateSalt: without it the salt
		// is all zero and two hashes of the same password would be identical
		byte[] first = ScryptHasher.hash(pw());
		byte[] second = ScryptHasher.hash(pw());
		assertFalse(java.util.Arrays.equals(first, second));
	}

	@Test
	void scryptHashWithSaltWipesThePassword()
	{
		// kills the removed Arrays.fill(password, '\0') call in hashWithSalt
		char[] password = pw();
		ScryptHasher.hashWithSalt(password, new byte[ScryptHasher.SALT_LENGTH], ScryptHasher.MIN_N,
			ScryptHasher.MIN_R, ScryptHasher.MIN_P, 32);
		assertTrue(allZero(password), "password array must be wiped after hashWithSalt");
	}

	@Test
	void scryptVerifyWipesThePasswordAndReturnsCorrectResult()
	{
		// kills the removed Arrays.fill(password, '\0') call in verify
		byte[] salt = new byte[ScryptHasher.SALT_LENGTH];
		byte[] expected = ScryptHasher.hashWithSalt(pw(), salt, ScryptHasher.MIN_N,
			ScryptHasher.MIN_R, ScryptHasher.MIN_P, 32);
		char[] password = pw();
		assertTrue(ScryptHasher.verify(password, salt, expected, ScryptHasher.MIN_N,
			ScryptHasher.MIN_R, ScryptHasher.MIN_P));
		assertTrue(allZero(password), "password array must be wiped after verify");

		char[] wrong = "wrong".toCharArray();
		assertFalse(ScryptHasher.verify(wrong, salt, expected, ScryptHasher.MIN_N,
			ScryptHasher.MIN_R, ScryptHasher.MIN_P));
	}

	// ----- BLAKE2b ----------------------------------------------------------

	@Test
	void blake2bAcceptsDigestLengthBoundaries()
	{
		// kills both "changed conditional boundary" mutants on the digest length guard: MIN and
		// MAX must be accepted and produce an output of exactly that length
		assertEquals(Blake2bHasher.MIN_DIGEST_LENGTH,
			Blake2bHasher.hash(DATA, Blake2bHasher.MIN_DIGEST_LENGTH).length);
		assertEquals(Blake2bHasher.MAX_DIGEST_LENGTH,
			Blake2bHasher.hash(DATA, Blake2bHasher.MAX_DIGEST_LENGTH).length);
	}

	@Test
	void blake2bStringHashUsesTheDefaultDigestLength()
	{
		// kills the "replaced return value with null" mutant of hash(String, Charset) and asserts
		// it delegates to the default digest length
		byte[] hash = Blake2bHasher.hash("payload", StandardCharsets.UTF_8);
		assertNotNull(hash);
		assertEquals(Blake2bHasher.DEFAULT_DIGEST_LENGTH, hash.length);
		assertArrayEquals(Blake2bHasher.hash("payload", StandardCharsets.UTF_8,
			Blake2bHasher.DEFAULT_DIGEST_LENGTH), hash);
	}

	@Test
	void blake2bKeyedHashAcceptsBoundaryKeyLengthAndDigestLength()
	{
		// kills the "key.length > 64" boundary mutant: a key of exactly the max length is valid
		byte[] maxKey = new byte[64];
		assertNotNull(Blake2bHasher.hashWithKey(DATA, maxKey, Blake2bHasher.DEFAULT_DIGEST_LENGTH));
		// a key one byte too long must still be rejected
		assertThrows(IllegalArgumentException.class, () -> Blake2bHasher.hashWithKey(DATA,
			new byte[65], Blake2bHasher.DEFAULT_DIGEST_LENGTH));
		// kills both digest length boundary mutants on the keyed overload
		assertEquals(Blake2bHasher.MIN_DIGEST_LENGTH,
			Blake2bHasher.hashWithKey(DATA, maxKey, Blake2bHasher.MIN_DIGEST_LENGTH).length);
		assertEquals(Blake2bHasher.MAX_DIGEST_LENGTH,
			Blake2bHasher.hashWithKey(DATA, maxKey, Blake2bHasher.MAX_DIGEST_LENGTH).length);
	}

	// ----- BLAKE2s ----------------------------------------------------------

	@Test
	void blake2sAcceptsDigestLengthBoundaries()
	{
		assertEquals(Blake2sHasher.MIN_DIGEST_LENGTH,
			Blake2sHasher.hash(DATA, Blake2sHasher.MIN_DIGEST_LENGTH).length);
		assertEquals(Blake2sHasher.MAX_DIGEST_LENGTH,
			Blake2sHasher.hash(DATA, Blake2sHasher.MAX_DIGEST_LENGTH).length);
	}

	@Test
	void blake2sStringHashUsesTheDefaultDigestLength()
	{
		byte[] hash = Blake2sHasher.hash("payload", StandardCharsets.UTF_8);
		assertNotNull(hash);
		assertEquals(Blake2sHasher.DEFAULT_DIGEST_LENGTH, hash.length);
		assertArrayEquals(Blake2sHasher.hash("payload", StandardCharsets.UTF_8,
			Blake2sHasher.DEFAULT_DIGEST_LENGTH), hash);
	}

	@Test
	void blake2sKeyedHashAcceptsBoundaryKeyLengthAndDigestLength()
	{
		byte[] maxKey = new byte[32];
		assertNotNull(Blake2sHasher.hashWithKey(DATA, maxKey, Blake2sHasher.DEFAULT_DIGEST_LENGTH));
		assertThrows(IllegalArgumentException.class, () -> Blake2sHasher.hashWithKey(DATA,
			new byte[33], Blake2sHasher.DEFAULT_DIGEST_LENGTH));
		assertEquals(Blake2sHasher.MIN_DIGEST_LENGTH,
			Blake2sHasher.hashWithKey(DATA, maxKey, Blake2sHasher.MIN_DIGEST_LENGTH).length);
		assertEquals(Blake2sHasher.MAX_DIGEST_LENGTH,
			Blake2sHasher.hashWithKey(DATA, maxKey, Blake2sHasher.MAX_DIGEST_LENGTH).length);
	}
}
