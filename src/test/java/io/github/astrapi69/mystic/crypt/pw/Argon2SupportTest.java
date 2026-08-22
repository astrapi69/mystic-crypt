/**
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The unit test class for the class {@link Argon2Support}
 */
public class Argon2SupportTest
{

	private static final String PASSWORD = "correct horse battery staple";

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
		return Stream.of(new MalformedHashCase("not an encoded hash at all", "not-a-valid-hash"),
			new MalformedHashCase("wrong argon2 variant",
				"$argon2i$v=19$m=8,t=1,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaA"),
			new MalformedHashCase("missing parallelism parameter",
				"$argon2id$v=19$m=8,t=1$c2FsdHNhbHRzYWx0c2E$aGFzaA"),
			new MalformedHashCase("parameter without a value",
				"$argon2id$v=19$m=8,t=1,p$c2FsdHNhbHRzYWx0c2E$aGFzaA"),
			new MalformedHashCase("unknown parameter",
				"$argon2id$v=19$m=8,t=1,x=1$c2FsdHNhbHRzYWx0c2E$aGFzaA"),
			new MalformedHashCase("negative memory parameter",
				"$argon2id$v=19$m=-8,t=1,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaA"),
			new MalformedHashCase("negative iterations parameter",
				"$argon2id$v=19$m=8,t=-1,p=1$c2FsdHNhbHRzYWx0c2E$aGFzaA"),
			new MalformedHashCase("negative parallelism parameter",
				"$argon2id$v=19$m=8,t=1,p=-1$c2FsdHNhbHRzYWx0c2E$aGFzaA"),
			new MalformedHashCase("too few parts", "$argon2id$v=19$m=8,t=1,p=1$c2FsdA"));
	}

	/**
	 * Test method for {@link Argon2Support#verify(char[], String)}, a malformed encoded hash never
	 * verifies but also never propagates an exception
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("malformedHashCases")
	public void verify_answersFalseForAMalformedEncodedHash(final MalformedHashCase testCase)
	{
		assertFalse(Argon2Support.verify(PASSWORD.toCharArray(), testCase.encoded()));
	}

	/**
	 * Test method for {@link Argon2Support#hash(char[])} and
	 * {@link Argon2Support#verify(char[], String)}, only the very same password verifies
	 */
	@Test
	public void hash_createsAnEncodedHashThatOnlyVerifiesTheSamePassword()
	{
		String encoded = Argon2Support.hash(PASSWORD.toCharArray());

		assertTrue(encoded.startsWith("$argon2id$"));
		assertTrue(Argon2Support.verify(PASSWORD.toCharArray(), encoded));
		assertFalse(Argon2Support.verify("wrong password".toCharArray(), encoded));
	}

	/**
	 * Test method for {@link Argon2Support#verify(char[], String)}, a tampered hash does not verify
	 */
	@Test
	public void verify_answersFalseForATamperedHash()
	{
		String encoded = Argon2Support.hash(PASSWORD.toCharArray());
		String tampered = encoded.substring(0, encoded.length() - 1)
			+ (encoded.charAt(encoded.length() - 1) == 'A' ? 'B' : 'A');

		assertFalse(Argon2Support.verify(PASSWORD.toCharArray(), tampered));
	}

	/**
	 * Test method for {@link Argon2Support#hash(char[])} and
	 * {@link Argon2Support#verify(char[], String)}, both arguments are mandatory
	 */
	@Test
	public void hashAndVerify_rejectNullArguments()
	{
		String encoded = Argon2Support.hash(PASSWORD.toCharArray());

		assertThrows(NullPointerException.class, () -> Argon2Support.hash(null));
		assertThrows(NullPointerException.class, () -> Argon2Support.verify(null, encoded));
		assertThrows(NullPointerException.class,
			() -> Argon2Support.verify(PASSWORD.toCharArray(), null));
	}
}
