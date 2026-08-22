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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.mystic.crypt.secret.FeldmanVSS.Share;
import io.github.astrapi69.mystic.crypt.secret.FeldmanVSS.ShareGenerationResult;

/**
 * Unit tests for {@link FeldmanVSS}.
 *
 * @author Asterios Raptis
 * @since 10.4
 */
class FeldmanVSSTest
{

	/**
	 * Test method for {@link FeldmanVSS#findGenerator(BigInteger, BigInteger, SecureRandom)}, a
	 * drawn candidate whose value collapses to 1 (its (p-1)/q-th power is 1) must be rejected and
	 * the search must retry with the next candidate. The first {@code nextBytes} call is forced to
	 * all zeros so that the candidate becomes 1 and the retry branch of the do/while loop is taken
	 * exactly once; the second call falls back to real randomness and yields a valid generator of
	 * the subgroup of order q.
	 */
	@Test
	void findGenerator_retriesWhenTheDrawnCandidateIsNotAGenerator()
	{
		// 23 is a safe prime: 23 = 2 * 11 + 1 with q = 11 prime, so the subgroup has order 11
		final BigInteger p = BigInteger.valueOf(23);
		final BigInteger q = BigInteger.valueOf(11);
		final SecureRandom forcingOneRetry = new SecureRandom()
		{
			private static final long serialVersionUID = 1L;
			private int calls = 0;

			@Override
			public void nextBytes(final byte[] bytes)
			{
				if (calls++ == 0)
				{
					// all zeros -> candidate BigInteger 0 -> h = 1 -> 1^((p-1)/q) == 1 -> retry
					Arrays.fill(bytes, (byte)0);
				}
				else
				{
					super.nextBytes(bytes);
				}
			}
		};

		final BigInteger generator = FeldmanVSS.findGenerator(p, q, forcingOneRetry);

		assertNotNull(generator);
		assertNotEquals(BigInteger.ONE, generator, "1 is not a valid generator");
		assertEquals(BigInteger.ONE, generator.modPow(q, p),
			"the generator must have order dividing q");
	}

	@Test
	void testSplitSecretWithDefaults()
	{
		byte[] secret = "MySecretKey12345".getBytes();

		ShareGenerationResult result = FeldmanVSS.splitSecret(secret);

		assertNotNull(result);
		assertNotNull(result.getShares());
		assertNotNull(result.getCommitments());
		assertNotNull(result.getSecret());

		assertEquals(FeldmanVSS.DEFAULT_N_SHARES, result.getShares().size());
		assertEquals(FeldmanVSS.DEFAULT_THRESHOLD, result.getCommitments().getValues().size());
	}

	@Test
	void testSplitSecretWithCustomParameters()
	{
		byte[] secret = "CustomSecret".getBytes();
		int threshold = 4;
		int nShares = 7;

		ShareGenerationResult result = FeldmanVSS.splitSecret(secret, threshold, nShares);

		assertNotNull(result);
		assertEquals(nShares, result.getShares().size());
		assertEquals(threshold, result.getCommitments().getValues().size());
	}

	@Test
	void testShareVerification()
	{
		byte[] secret = "TestSecretForVerification".getBytes();

		ShareGenerationResult result = FeldmanVSS.splitSecret(secret, 3, 5);

		// All shares should be valid
		for (Share share : result.getShares())
		{
			assertTrue(FeldmanVSS.verifyShare(share, result.getCommitments()),
				"Share " + share.getIndex() + " should be valid");
		}
	}

	@Test
	void testMultipleShareVerification()
	{
		byte[] secret = "MultiShareTest".getBytes();

		ShareGenerationResult result = FeldmanVSS.splitSecret(secret, 3, 5);

		List<Integer> invalidIndices = FeldmanVSS.verifyShares(result.getShares(),
			result.getCommitments());

		assertTrue(invalidIndices.isEmpty(), "All shares should be valid");
	}

	@Test
	void testReconstructSecretWithThresholdShares()
	{
		byte[] originalSecret = "ReconstructionTestSecret".getBytes();

		ShareGenerationResult result = FeldmanVSS.splitSecret(originalSecret, 3, 5);

		// Use exactly threshold number of shares
		List<Share> subset = result.getShares().subList(0, 3);

		BigInteger reconstructed = FeldmanVSS.reconstructSecret(subset, result.getCommitments(),
			result.getCommitments().getQ());

		assertEquals(result.getSecret(), reconstructed,
			"Reconstructed secret should match original");
	}

	@Test
	void testReconstructSecretWithMoreThanThresholdShares()
	{
		byte[] originalSecret = "ExtraSharesTest".getBytes();

		ShareGenerationResult result = FeldmanVSS.splitSecret(originalSecret, 3, 5);

		// Use all 5 shares (more than threshold)
		BigInteger reconstructed = FeldmanVSS.reconstructSecret(result.getShares(),
			result.getCommitments(), result.getCommitments().getQ());

		assertEquals(result.getSecret(), reconstructed,
			"Reconstructed secret should match original with extra shares");
	}

	@Test
	void testReconstructSecretBytes()
	{
		byte[] originalSecret = "ByteTest".getBytes();
		int expectedLength = 32;

		ShareGenerationResult result = FeldmanVSS.splitSecret(originalSecret, 3, 5);

		List<Share> subset = result.getShares().subList(0, 3);

		BigInteger reconstructed = FeldmanVSS.reconstructSecret(subset, result.getCommitments(),
			result.getCommitments().getQ());

		assertEquals(result.getSecret(), reconstructed, "Reconstructed BigInteger should match");
	}

	@Test
	void testInsufficientSharesThrowsException()
	{
		byte[] secret = "InsufficientSharesTest".getBytes();

		ShareGenerationResult result = FeldmanVSS.splitSecret(secret, 4, 6);

		// Try to reconstruct with only 2 shares (threshold is 4)
		List<Share> insufficientSubset = result.getShares().subList(0, 2);

		IllegalArgumentException exception = org.junit.jupiter.api.Assertions
			.assertThrows(IllegalArgumentException.class, () -> {
				FeldmanVSS.reconstructSecret(insufficientSubset, result.getCommitments(),
					result.getCommitments().getQ());
			});

		assertTrue(exception.getMessage().contains("Insufficient shares"));
	}

	@Test
	void testTamperedShareDetection()
	{
		byte[] secret = "TamperDetectionTest".getBytes();

		ShareGenerationResult result = FeldmanVSS.splitSecret(secret, 3, 5);

		// Tamper with one share
		List<Share> shares = result.getShares();
		Share tamperedShare = new Share(shares.get(0).getIndex(),
			shares.get(0).getValue().add(BigInteger.ONE));

		List<Share> tamperedShares = Arrays.asList(tamperedShare, shares.get(1), shares.get(2));

		// Verification should detect the tampered share
		IllegalStateException exception = org.junit.jupiter.api.Assertions
			.assertThrows(IllegalStateException.class, () -> {
				FeldmanVSS.reconstructSecret(tamperedShares, result.getCommitments(),
					result.getCommitments().getQ());
			});

		assertTrue(exception.getMessage().contains("Invalid shares"));
	}

	@Test
	void testToBigInteger()
	{
		byte[] data = { 0x01, 0x02, 0x03, 0x04 };

		BigInteger bigInt = FeldmanVSS.toBigInteger(data, 64);

		assertNotNull(bigInt);
		assertTrue(bigInt.signum() > 0, "BigInteger should be positive");
	}

	@Test
	void testRoundTripWithDifferentThresholds()
	{
		byte[] originalSecret = "VariableThresholdTest".getBytes();

		// Test with different threshold values
		for (int t = 2; t <= 5; t++)
		{
			ShareGenerationResult result = FeldmanVSS.splitSecret(originalSecret, t, t + 2);

			List<Share> subset = result.getShares().subList(0, t);

			byte[] reconstructed = FeldmanVSS.reconstructSecretBytes(subset,
				result.getCommitments(), result.getCommitments().getQ(), originalSecret.length);

			assertArrayEquals(originalSecret, reconstructed,
				"Round-trip should work for threshold=" + t);
		}
	}

	@Test
	void testEmptySharesThrowsException()
	{
		byte[] secret = "EmptySharesTest".getBytes();
		ShareGenerationResult result = FeldmanVSS.splitSecret(secret, 3, 5);

		IllegalArgumentException exception = org.junit.jupiter.api.Assertions
			.assertThrows(IllegalArgumentException.class, () -> {
				FeldmanVSS.reconstructSecret(Arrays.asList(), result.getCommitments(),
					result.getCommitments().getQ());
			});

		assertTrue(exception.getMessage().contains("No shares provided"));
	}
}
