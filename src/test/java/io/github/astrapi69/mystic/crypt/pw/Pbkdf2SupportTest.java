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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.NoSuchAlgorithmException;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The unit test class for the class {@link Pbkdf2Support}
 */
public class Pbkdf2SupportTest
{

	private static final String PASSWORD = "correct horse battery staple";

	/**
	 * Test method for {@link Pbkdf2Support#hash(char[])} and
	 * {@link Pbkdf2Support#verify(char[], String)}
	 */
	@Test
	public void testHashAndVerify()
	{
		final String encoded = Pbkdf2Support.hash(PASSWORD.toCharArray());

		assertTrue(Pbkdf2Support.verify(PASSWORD.toCharArray(), encoded));
	}

	/**
	 * Test method for {@link Pbkdf2Support#verify(char[], String)} with the wrong password
	 */
	@Test
	public void testVerifyFailsForWrongPassword()
	{
		final String encoded = Pbkdf2Support.hash(PASSWORD.toCharArray());

		assertFalse(Pbkdf2Support.verify("wrong password".toCharArray(), encoded));
	}

	/**
	 * Test method for {@link Pbkdf2Support#hash(char[])} confirming two hashes of the same password
	 * differ (random salt per call)
	 */
	@Test
	public void testHashIsNonDeterministic()
	{
		final String first = Pbkdf2Support.hash(PASSWORD.toCharArray());
		final String second = Pbkdf2Support.hash(PASSWORD.toCharArray());

		assertNotEquals(first, second);
		assertTrue(Pbkdf2Support.verify(PASSWORD.toCharArray(), first));
		assertTrue(Pbkdf2Support.verify(PASSWORD.toCharArray(), second));
	}

	/**
	 * Test method for {@link Pbkdf2Support#verify(char[], String)} with a tampered encoded hash
	 */
	@Test
	public void testVerifyFailsForTamperedHash()
	{
		final String encoded = Pbkdf2Support.hash(PASSWORD.toCharArray());
		// flip the first character of the hash part: the trailing character of an unpadded base64
		// string carries bits the decoder ignores, so it is not guaranteed to change the hash
		final int hashStart = encoded.lastIndexOf('$') + 1;
		final char original = encoded.charAt(hashStart);
		final String tampered = encoded.substring(0, hashStart) + (original == 'A' ? 'B' : 'A')
			+ encoded.substring(hashStart + 1);

		assertNotEquals(encoded, tampered);
		assertFalse(Pbkdf2Support.verify(PASSWORD.toCharArray(), tampered));
	}

	/**
	 * Test method for {@link Pbkdf2Support#verify(char[], String)} with a malformed encoded string
	 */
	@Test
	public void testVerifyFailsForMalformedEncoded()
	{
		assertFalse(Pbkdf2Support.verify("password".toCharArray(), "not-a-valid-hash"));
	}

	/**
	 * Test method for {@link Pbkdf2Support#hash(char[])} confirming the password array is zeroed
	 * after use
	 */
	@Test
	public void testHashZeroesPasswordArray()
	{
		final char[] password = PASSWORD.toCharArray();

		Pbkdf2Support.hash(password);

		for (final char c : password)
		{
			assertTrue(c == '\0');
		}
	}

	/**
	 * Test method for {@link Pbkdf2Support#verify(char[], String)} confirming the password array is
	 * zeroed after use
	 */
	@Test
	public void testVerifyZeroesPasswordArray()
	{
		final String encoded = Pbkdf2Support.hash(PASSWORD.toCharArray());
		final char[] password = PASSWORD.toCharArray();

		Pbkdf2Support.verify(password, encoded);

		for (final char c : password)
		{
			assertTrue(c == '\0');
		}
	}

	/**
	 * A scenario with an encoded hash that can not be verified
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param encoded
	 *            the malformed encoded hash
	 */
	record MalformedHashCase(String description, String encoded) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static Stream<MalformedHashCase> malformedHashCases()
	{
		return Stream.of(new MalformedHashCase("too few parts", "$pbkdf2-sha256$i=1000$c2FsdA"),
			new MalformedHashCase("wrong algorithm identifier",
				"$argon2id$i=1000$c2FsdHNhbHRzYWx0c2E$aGFzaA"),
			new MalformedHashCase("iteration parameter without the i= prefix",
				"$pbkdf2-sha256$x=1000$c2FsdHNhbHRzYWx0c2E$aGFzaA"),
			new MalformedHashCase("iteration count is not a number",
				"$pbkdf2-sha256$i=not-a-number$c2FsdHNhbHRzYWx0c2E$aGFzaA"));
	}

	/**
	 * Test method for {@link Pbkdf2Support#verify(char[], String)}, a malformed encoded hash never
	 * verifies but also never propagates an exception
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("malformedHashCases")
	public void testVerifyFailsForEveryMalformedEncoding(final MalformedHashCase testCase)
	{
		assertFalse(Pbkdf2Support.verify(PASSWORD.toCharArray(), testCase.encoded()));
	}

	/**
	 * Test method for {@link Pbkdf2Support#hash(char[])} and
	 * {@link Pbkdf2Support#verify(char[], String)}, both arguments are mandatory
	 */
	@Test
	public void testHashAndVerifyRejectNullArguments()
	{
		final String encoded = Pbkdf2Support.hash(PASSWORD.toCharArray());

		assertThrows(NullPointerException.class, () -> Pbkdf2Support.hash(null));
		assertThrows(NullPointerException.class, () -> Pbkdf2Support.verify(null, encoded));
		assertThrows(NullPointerException.class,
			() -> Pbkdf2Support.verify(PASSWORD.toCharArray(), null));
	}

	/**
	 * The checked {@link NoSuchAlgorithmException} that
	 * {@link javax.crypto.SecretKeyFactory#getInstance(String)} declares can not be triggered
	 * through the fixed {@code PBKDF2WithHmacSHA256} algorithm, but it must still be handled. The
	 * extracted overload {@link Pbkdf2Support#rawHash(char[], byte[], int, String)} lets a test
	 * drive it with an unknown algorithm name, which must be rethrown as an
	 * {@link IllegalStateException} keeping the original cause.
	 */
	@Test
	public void rawHash_rethrowsAnUnknownAlgorithmAsIllegalState()
	{
		IllegalStateException exception = assertThrows(IllegalStateException.class,
			() -> Pbkdf2Support.rawHash(PASSWORD.toCharArray(), new byte[16], 1000,
				"PBKDF2WithHmacTHIS_IS_NOT_REAL"));
		assertInstanceOf(NoSuchAlgorithmException.class, exception.getCause());
	}
}
