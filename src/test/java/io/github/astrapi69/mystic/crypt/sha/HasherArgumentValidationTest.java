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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The unit test class for the argument validation of the hasher classes {@link BcryptHasher},
 * {@link ScryptHasher}, {@link Blake2bHasher} and {@link Blake2sHasher}
 */
class HasherArgumentValidationTest
{

	private static final char[] PASSWORD = "correct horse battery staple".toCharArray();

	private static final byte[] DATA = "the quick brown fox".getBytes(StandardCharsets.UTF_8);

	private static final byte[] SALT_16 = new byte[16];

	/**
	 * A scenario with a call that has to be rejected
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param executable
	 *            the call that has to be rejected
	 * @param expectedMessage
	 *            the expected message of the thrown exception
	 */
	record RejectedCallCase(String description, Executable executable, String expectedMessage) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static Stream<RejectedCallCase> rejectedBcryptCalls()
	{
		return Stream.of(
			new RejectedCallCase("hash with salt without a password",
				() -> BcryptHasher.hashWithSalt(null, SALT_16, BcryptHasher.DEFAULT_LOG_ROUNDS),
				"Password cannot be null"),
			new RejectedCallCase("hash with salt without a salt",
				() -> BcryptHasher.hashWithSalt(PASSWORD.clone(), null,
					BcryptHasher.DEFAULT_LOG_ROUNDS),
				"Salt cannot be null"),
			new RejectedCallCase("hash with salt and too few log rounds",
				() -> BcryptHasher.hashWithSalt(PASSWORD.clone(), SALT_16,
					BcryptHasher.MIN_LOG_ROUNDS - 1),
				"Log rounds must be between " + BcryptHasher.MIN_LOG_ROUNDS + " and "
					+ BcryptHasher.MAX_LOG_ROUNDS),
			new RejectedCallCase("hash with salt and too many log rounds",
				() -> BcryptHasher.hashWithSalt(PASSWORD.clone(), SALT_16,
					BcryptHasher.MAX_LOG_ROUNDS + 1),
				"Log rounds must be between " + BcryptHasher.MIN_LOG_ROUNDS + " and "
					+ BcryptHasher.MAX_LOG_ROUNDS),
			new RejectedCallCase("log rounds of a null hash", () -> BcryptHasher.getLogRounds(null),
				"Hash cannot be null"),
			new RejectedCallCase("log rounds of a hash without the bcrypt structure",
				() -> BcryptHasher.getLogRounds("not-a-bcrypt-hash"), "Invalid BCrypt hash format"),
			new RejectedCallCase("log rounds of a hash of another algorithm",
				() -> BcryptHasher.getLogRounds("$1$10$abcdefghijklmnopqrstuv"),
				"Invalid BCrypt hash format"),
			new RejectedCallCase("log rounds that are not a number",
				() -> BcryptHasher.getLogRounds("$2a$xy$abcdefghijklmnopqrstuv"),
				"Invalid BCrypt hash format"));
	}

	static Stream<RejectedCallCase> rejectedScryptCalls()
	{
		return Stream.of(
			new RejectedCallCase("hash with salt without a password",
				() -> ScryptHasher.hashWithSalt(null, SALT_16, ScryptHasher.MIN_N, 1, 1, 32),
				"Password cannot be null"),
			new RejectedCallCase("hash with salt without a salt",
				() -> ScryptHasher.hashWithSalt(PASSWORD.clone(), null, ScryptHasher.MIN_N, 1, 1,
					32),
				"Salt cannot be null"),
			new RejectedCallCase("hash with a block size below the minimum",
				() -> ScryptHasher.hashWithSalt(PASSWORD.clone(), SALT_16, ScryptHasher.MIN_N,
					ScryptHasher.MIN_R - 1, 1, 32),
				"R must be at least " + ScryptHasher.MIN_R),
			new RejectedCallCase("hash with a parallelism below the minimum",
				() -> ScryptHasher.hashWithSalt(PASSWORD.clone(), SALT_16, ScryptHasher.MIN_N, 1,
					ScryptHasher.MIN_P - 1, 32),
				"P must be at least " + ScryptHasher.MIN_P),
			new RejectedCallCase("verify without an expected hash",
				() -> ScryptHasher.verify(PASSWORD.clone(), SALT_16, null, ScryptHasher.MIN_N, 1,
					1),
				"Expected hash cannot be null"),
			new RejectedCallCase("verify without the salt and hash block",
				() -> ScryptHasher.verify(PASSWORD.clone(), null, ScryptHasher.MIN_N, 1, 1),
				"saltAndHash cannot be null"),
			new RejectedCallCase("verify with a salt and hash block without a hash",
				() -> ScryptHasher.verify(PASSWORD.clone(), new byte[ScryptHasher.SALT_LENGTH],
					ScryptHasher.MIN_N, 1, 1),
				"saltAndHash is too short"));
	}

	static Stream<RejectedCallCase> rejectedBlake2Calls()
	{
		return Stream.of(
			new RejectedCallCase("blake2b string hash without data",
				() -> Blake2bHasher.hash((String)null, StandardCharsets.UTF_8,
					Blake2bHasher.DEFAULT_DIGEST_LENGTH),
				"Data cannot be null"),
			new RejectedCallCase("blake2b keyed hash without data",
				() -> Blake2bHasher.hashWithKey(null, SALT_16, Blake2bHasher.DEFAULT_DIGEST_LENGTH),
				"Data cannot be null"),
			new RejectedCallCase("blake2b keyed hash with a digest length below the minimum",
				() -> Blake2bHasher.hashWithKey(DATA, SALT_16, Blake2bHasher.MIN_DIGEST_LENGTH - 1),
				"Digest length must be between " + Blake2bHasher.MIN_DIGEST_LENGTH + " and "
					+ Blake2bHasher.MAX_DIGEST_LENGTH),
			new RejectedCallCase("blake2b keyed hash with a digest length above the maximum",
				() -> Blake2bHasher.hashWithKey(DATA, SALT_16, Blake2bHasher.MAX_DIGEST_LENGTH + 1),
				"Digest length must be between " + Blake2bHasher.MIN_DIGEST_LENGTH + " and "
					+ Blake2bHasher.MAX_DIGEST_LENGTH),
			new RejectedCallCase("blake2s string hash without data",
				() -> Blake2sHasher.hash((String)null, StandardCharsets.UTF_8,
					Blake2sHasher.DEFAULT_DIGEST_LENGTH),
				"Data cannot be null"),
			new RejectedCallCase("blake2s keyed hash without data",
				() -> Blake2sHasher.hashWithKey(null, SALT_16, Blake2sHasher.DEFAULT_DIGEST_LENGTH),
				"Data cannot be null"),
			new RejectedCallCase("blake2s keyed hash with a digest length below the minimum",
				() -> Blake2sHasher.hashWithKey(DATA, SALT_16, Blake2sHasher.MIN_DIGEST_LENGTH - 1),
				"Digest length must be between " + Blake2sHasher.MIN_DIGEST_LENGTH + " and "
					+ Blake2sHasher.MAX_DIGEST_LENGTH),
			new RejectedCallCase("blake2s keyed hash with a digest length above the maximum",
				() -> Blake2sHasher.hashWithKey(DATA, SALT_16, Blake2sHasher.MAX_DIGEST_LENGTH + 1),
				"Digest length must be between " + Blake2sHasher.MIN_DIGEST_LENGTH + " and "
					+ Blake2sHasher.MAX_DIGEST_LENGTH));
	}

	/**
	 * Test method for the argument validation of {@link BcryptHasher}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("rejectedBcryptCalls")
	void everyInvalidBcryptCallIsRejected(final RejectedCallCase testCase)
	{
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
			testCase.executable());

		assertEquals(testCase.expectedMessage(), exception.getMessage());
	}

	/**
	 * Test method for the argument validation of {@link ScryptHasher}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("rejectedScryptCalls")
	void everyInvalidScryptCallIsRejected(final RejectedCallCase testCase)
	{
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
			testCase.executable());

		assertEquals(testCase.expectedMessage(), exception.getMessage());
	}

	/**
	 * Test method for the argument validation of {@link Blake2bHasher} and {@link Blake2sHasher}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("rejectedBlake2Calls")
	void everyInvalidBlake2CallIsRejected(final RejectedCallCase testCase)
	{
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
			testCase.executable());

		assertEquals(testCase.expectedMessage(), exception.getMessage());
	}
}
