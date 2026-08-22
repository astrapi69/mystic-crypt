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
package io.github.astrapi69.mystic.crypt.algorithm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.stream.Stream;

import javax.crypto.Cipher;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The unit test class for the enum {@link MysticSymmetricAlgorithm}
 */
public class MysticSymmetricAlgorithmTest
{

	/**
	 * A scenario with the expected transformation of an algorithm
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param expectedTransformation
	 *            the expected transformation string
	 */
	record AlgorithmCase(MysticSymmetricAlgorithm algorithm, String expectedTransformation) {
		@Override
		public String toString()
		{
			return algorithm.name();
		}
	}

	static Stream<AlgorithmCase> algorithmCases()
	{
		return Stream.of(
			new AlgorithmCase(MysticSymmetricAlgorithm.AES_GCM_NO_PADDING, "AES/GCM/NoPadding"),
			new AlgorithmCase(MysticSymmetricAlgorithm.CHACHA20_POLY1305, "ChaCha20-Poly1305"));
	}

	/**
	 * Test method for {@link MysticSymmetricAlgorithm#getAlgorithm()} and
	 * {@link MysticSymmetricAlgorithm#toString()}, both answer the transformation string
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("algorithmCases")
	public void getAlgorithmAndToString_answerTheTransformation(final AlgorithmCase testCase)
	{
		assertEquals(testCase.expectedTransformation(), testCase.algorithm().getAlgorithm());
		assertEquals(testCase.expectedTransformation(), testCase.algorithm().toString());
	}

	/**
	 * Test method for {@link MysticSymmetricAlgorithm#getAlgorithm()}, every transformation of this
	 * enum has to be resolvable by the java cryptography architecture
	 *
	 * @param algorithm
	 *            the algorithm
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@ParameterizedTest
	@EnumSource(MysticSymmetricAlgorithm.class)
	public void everyAlgorithmIsAKnownTransformation(final MysticSymmetricAlgorithm algorithm)
		throws Exception
	{
		assertNotNull(Cipher.getInstance(algorithm.getAlgorithm()));
	}
}
