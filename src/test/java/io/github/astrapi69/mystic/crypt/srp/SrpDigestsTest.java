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
package io.github.astrapi69.mystic.crypt.srp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.stream.Stream;

import org.bouncycastle.crypto.Digest;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The unit test class for the class {@link SrpDigests}
 */
class SrpDigestsTest
{

	/**
	 * A scenario with a supported hash algorithm
	 *
	 * @param algorithm
	 *            the name of the hash algorithm
	 * @param expectedDigestName
	 *            the expected name of the created digest
	 * @param expectedDigestSize
	 *            the expected size in bytes of the created digest
	 */
	record SupportedAlgorithmCase(String algorithm, String expectedDigestName,
		int expectedDigestSize) {
		@Override
		public String toString()
		{
			return algorithm;
		}
	}

	static Stream<SupportedAlgorithmCase> supportedAlgorithmCases()
	{
		return Stream.of(new SupportedAlgorithmCase("SHA-1", "SHA-1", 20),
			new SupportedAlgorithmCase("SHA-224", "SHA-224", 28),
			new SupportedAlgorithmCase("SHA-256", "SHA-256", 32),
			new SupportedAlgorithmCase("SHA-384", "SHA-384", 48),
			new SupportedAlgorithmCase("SHA-512", "SHA-512", 64),
			new SupportedAlgorithmCase("SHA3-256", "SHA3-256", 32));
	}

	/**
	 * Test method for {@link SrpDigests#newDigest(String)}, every supported algorithm name has to
	 * answer the matching digest
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("supportedAlgorithmCases")
	void newDigest_answersTheDigestOfTheGivenAlgorithm(final SupportedAlgorithmCase testCase)
	{
		Digest digest = SrpDigests.newDigest(testCase.algorithm());

		assertEquals(testCase.expectedDigestName(), digest.getAlgorithmName());
		assertEquals(testCase.expectedDigestSize(), digest.getDigestSize());
	}

	/**
	 * Test method for {@link SrpDigests#newDigest(String)}, an unsupported algorithm name has to be
	 * rejected
	 *
	 * @param algorithm
	 *            the unsupported algorithm name
	 */
	@ParameterizedTest
	@ValueSource(strings = { "MD5", "SHA-512/256", "sha-256", "SHA3-512", "" })
	void newDigest_rejectsAnUnsupportedAlgorithm(final String algorithm)
	{
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
			() -> SrpDigests.newDigest(algorithm));

		assertEquals("Unsupported hash algorithm: " + algorithm, exception.getMessage());
	}
}
