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
package io.github.astrapi69.mystic.crypt.secret;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.mystic.crypt.secret.FeldmanVSS.Share;
import io.github.astrapi69.mystic.crypt.secret.FeldmanVSS.ShareGenerationResult;

/**
 * The unit test class for the edge cases of the class {@link FeldmanVSS}
 */
public class FeldmanVSSEdgeCasesTest
{

	/**
	 * A scenario for an invalid threshold/share count combination
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param threshold
	 *            the threshold
	 * @param nShares
	 *            the number of shares
	 */
	record InvalidThresholdCase(String description, int threshold, int nShares) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	/**
	 * A scenario for the byte length normalization of
	 * {@link FeldmanVSS#reconstructSecretBytes(List, FeldmanVSS.Commitments, BigInteger, int)}
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param secret
	 *            the secret to split
	 * @param expectedLength
	 *            the requested length of the reconstructed secret
	 * @param expected
	 *            the expected reconstructed bytes
	 */
	record ReconstructBytesCase(String description, byte[] secret, int expectedLength,
		byte[] expected) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static Stream<InvalidThresholdCase> invalidThresholdCases()
	{
		return Stream.of(new InvalidThresholdCase("threshold of zero", 0, 5),
			new InvalidThresholdCase("negative threshold", -1, 5),
			new InvalidThresholdCase("threshold greater than the share count", 6, 5));
	}

	static Stream<ReconstructBytesCase> reconstructBytesCases()
	{
		return Stream.of(
			new ReconstructBytesCase("exact length", new byte[] { 1, 2, 3, 4 }, 4,
				new byte[] { 1, 2, 3, 4 }),
			new ReconstructBytesCase("shorter secret is left padded with zeros",
				new byte[] { 1, 2, 3, 4 }, 8, new byte[] { 0, 0, 0, 0, 1, 2, 3, 4 }),
			new ReconstructBytesCase("longer secret keeps the least significant bytes",
				new byte[] { 1, 2, 3, 4 }, 2, new byte[] { 3, 4 }),
			new ReconstructBytesCase(
				"secret with a high bit set does not keep the sign byte of the BigInteger",
				new byte[] { (byte)0xff, 0x10 }, 2, new byte[] { (byte)0xff, 0x10 }),
			new ReconstructBytesCase("leading zero bytes of the secret are not recoverable",
				new byte[] { 0, 0, 7 }, 1, new byte[] { 7 }));
	}

	/**
	 * Test method for {@link FeldmanVSS#splitSecret(byte[], int, int)}, an invalid threshold has to
	 * be rejected
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("invalidThresholdCases")
	public void splitSecret_rejectsAnInvalidThreshold(final InvalidThresholdCase testCase)
	{
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
			() -> FeldmanVSS.splitSecret("secret".getBytes(), testCase.threshold(),
				testCase.nShares()));

		assertTrue(exception.getMessage().contains("Threshold"));
	}

	/**
	 * Test method for {@link FeldmanVSS#splitSecret(byte[], int, int)}, a threshold of one means
	 * that every single share reveals the secret
	 */
	@Test
	public void splitSecret_withAThresholdOfOne_everySingleShareReconstructsTheSecret()
	{
		byte[] secret = "single".getBytes();

		ShareGenerationResult result = FeldmanVSS.splitSecret(secret, 1, 3);

		for (Share share : result.getShares())
		{
			assertArrayEquals(secret, FeldmanVSS.reconstructSecretBytes(List.of(share),
				result.getCommitments(), result.getCommitments().getQ(), secret.length));
		}
	}

	/**
	 * Test method for {@link FeldmanVSS#splitSecret(byte[], int, int)}, a threshold equal to the
	 * share count is the maximum valid threshold and must be accepted (all shares are then required
	 * to reconstruct). This pins the upper boundary of the {@code threshold > nShares} check so a
	 * {@code >=} mutant is caught.
	 */
	@Test
	public void splitSecret_withAThresholdEqualToTheShareCount_isAcceptedAndReconstructs()
	{
		byte[] secret = "maximum".getBytes();

		ShareGenerationResult result = FeldmanVSS.splitSecret(secret, 3, 3);
		List<Share> shares = result.getShares();
		assertEquals(3, shares.size());

		assertArrayEquals(secret, FeldmanVSS.reconstructSecretBytes(shares, result.getCommitments(),
			result.getCommitments().getQ(), secret.length));
	}

	/**
	 * Test method for
	 * {@link FeldmanVSS#reconstructSecretBytes(List, FeldmanVSS.Commitments, BigInteger, int)}, the
	 * reconstructed bytes have to be normalized to the requested length
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("reconstructBytesCases")
	public void reconstructSecretBytes_normalizesTheResultToTheExpectedLength(
		final ReconstructBytesCase testCase)
	{
		ShareGenerationResult result = FeldmanVSS.splitSecret(testCase.secret(), 2, 3);

		byte[] reconstructed = FeldmanVSS.reconstructSecretBytes(result.getShares().subList(1, 3),
			result.getCommitments(), result.getCommitments().getQ(), testCase.expectedLength());

		assertArrayEquals(testCase.expected(), reconstructed);
	}

	/**
	 * Test method for {@link FeldmanVSS#toBigInteger(byte[], int)}, a bit length that is not a
	 * multiple of eight has to be rejected and a valid one has to keep the least significant bytes
	 */
	@Test
	public void toBigInteger_rejectsABitLengthThatIsNotAMultipleOfEight()
	{
		byte[] data = { 1, 2, 3, 4 };

		assertThrows(IllegalArgumentException.class, () -> FeldmanVSS.toBigInteger(data, 12));
		assertThrows(NullPointerException.class, () -> FeldmanVSS.toBigInteger(null, 16));
		assertEquals(new BigInteger(1, data), FeldmanVSS.toBigInteger(data, 32));
		assertEquals(new BigInteger(1, data), FeldmanVSS.toBigInteger(data, 64));
		assertEquals(new BigInteger(1, new byte[] { 3, 4 }), FeldmanVSS.toBigInteger(data, 16));
	}

	/**
	 * Test method for {@link Share#equals(Object)} and {@link Share#hashCode()}
	 */
	@Test
	public void share_equalsAndHashCode_dependOnIndexAndValue()
	{
		Share share = new Share(1, BigInteger.TEN);
		Share same = new Share(1, BigInteger.TEN);
		Share otherIndex = new Share(2, BigInteger.TEN);
		Share otherValue = new Share(1, BigInteger.ONE);

		assertEquals(share, share);
		assertEquals(share, same);
		assertEquals(share.hashCode(), same.hashCode());
		assertNotEquals(share, otherIndex);
		assertNotEquals(share, otherValue);
		assertNotEquals(share.hashCode(), otherIndex.hashCode());
		assertFalse(share.equals(null));
		assertFalse(share.equals("not a share"));
		assertThrows(NullPointerException.class, () -> new Share(1, null));
	}

	/**
	 * Test method for {@link FeldmanVSS#verifyShares(List, FeldmanVSS.Commitments)}, only the
	 * indexes of the tampered shares have to be reported
	 */
	@Test
	public void verifyShares_reportsOnlyTheTamperedShares()
	{
		ShareGenerationResult result = FeldmanVSS.splitSecret("tamper".getBytes(), 2, 4);
		List<Share> shares = result.getShares();
		Share tampered = new Share(shares.get(2).getIndex(),
			shares.get(2).getValue().add(BigInteger.ONE));
		List<Share> withTampered = Arrays.asList(shares.get(0), shares.get(1), tampered,
			shares.get(3));

		assertEquals(List.of(), FeldmanVSS.verifyShares(shares, result.getCommitments()));
		assertEquals(List.of(tampered.getIndex()),
			FeldmanVSS.verifyShares(withTampered, result.getCommitments()));
	}
}
