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
package io.github.astrapi69.mystic.crypt.secret;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * The class {@link FeldmanVSS} implements Feldman's Verifiable Secret Sharing scheme.
 * <p>
 * Feldman VSS extends Shamir's Secret Sharing by adding commitments that allow participants
 * to verify their shares before reconstruction. This prevents malicious dealers from distributing
 * invalid shares and detects reconstruction attempts with insufficient shares.
 * </p>
 * <p>
 * The scheme works in a prime order subgroup of Z_p* where p is a large prime and q divides p-1.
 * Commitments are computed as g^a_i mod p for each coefficient a_i of the sharing polynomial.
 * Participants can verify their share (i, s_i) by checking:
 * <pre>
 *   g^{s_i} ≡ ∏_{j=0}^{t-1} (C_j)^{i^j} mod p
 * </pre>
 * where C_j are the commitments.
 * </p>
 *
 * @author Asterios Raptis
 * @since 10.4
 */
public final class FeldmanVSS
{

	/** Default threshold for secret sharing (minimum shares needed). */
	public static final int DEFAULT_THRESHOLD = 3;

	/** Default number of total shares. */
	public static final int DEFAULT_N_SHARES = 5;

	/** Bit length for the prime p. */
	private static final int PRIME_BIT_LENGTH = 2048;

	/** Bit length for the prime q (subgroup order). */
	private static final int Q_BIT_LENGTH = 256;

	/** Generator for the subgroup. */
	private static final BigInteger GENERATOR = new BigInteger("2");

	private FeldmanVSS()
	{
	}

	/**
	 * Represents a share in the Feldman VSS scheme.
	 */
	public static final class Share
	{
		private final int index;
		private final BigInteger value;

		public Share(final int index, final BigInteger value)
		{
			this.index = index;
			this.value = Objects.requireNonNull(value);
		}

		public int getIndex()
		{
			return index;
		}

		public BigInteger getValue()
		{
			return value;
		}

		@Override
		public boolean equals(Object o)
		{
			if (this == o)
				return true;
			if (!(o instanceof Share))
				return false;
			Share share = (Share) o;
			return index == share.index && Objects.equals(value, share.value);
		}

		@Override
		public int hashCode()
		{
			return Objects.hash(index, value);
		}
	}

	/**
	 * Represents the public commitments for verification.
	 */
	public static final class Commitments
	{
		private final List<BigInteger> values;
		private final BigInteger p;
		private final BigInteger q;
		private final BigInteger g;

		public Commitments(final List<BigInteger> values, final BigInteger p, final BigInteger q,
			final BigInteger g)
		{
			this.values = Objects.requireNonNull(values);
			this.p = Objects.requireNonNull(p);
			this.q = Objects.requireNonNull(q);
			this.g = Objects.requireNonNull(g);
		}

		public List<BigInteger> getValues()
		{
			return new ArrayList<>(values);
		}

		public BigInteger getP()
		{
			return p;
		}

		public BigInteger getQ()
		{
			return q;
		}

		public BigInteger getG()
		{
			return g;
		}
	}

	/**
	 * Result of share generation containing shares and commitments.
	 */
	public static final class ShareGenerationResult
	{
		private final List<Share> shares;
		private final Commitments commitments;
		private final BigInteger secret;

		public ShareGenerationResult(final List<Share> shares, final Commitments commitments,
			final BigInteger secret)
		{
			this.shares = Objects.requireNonNull(shares);
			this.commitments = Objects.requireNonNull(commitments);
			this.secret = Objects.requireNonNull(secret);
		}

		public List<Share> getShares()
		{
			return new ArrayList<>(shares);
		}

		public Commitments getCommitments()
		{
			return commitments;
		}

		public BigInteger getSecret()
		{
			return secret;
		}
	}

	/**
	 * Generates safe primes p and q where q divides p-1.
	 *
	 * @return array with [p, q]
	 */
	private static BigInteger[] generateSafePrimes()
	{
		SecureRandom random = new SecureRandom();
		BigInteger q;
		BigInteger p;

		do
		{
			q = new BigInteger(Q_BIT_LENGTH, 1, random);
			p = q.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE);
		} while (!p.isProbablePrime(100));

		return new BigInteger[] { p, q };
	}

	/**
	 * Finds a generator for the subgroup of order q in Z_p*.
	 *
	 * @param p the large prime
	 * @param q the subgroup order (q divides p-1)
	 * @return a generator g
	 */
	private static BigInteger findGenerator(BigInteger p, BigInteger q)
	{
		SecureRandom random = new SecureRandom();
		BigInteger h;

		do
		{
			h = new BigInteger(p.bitLength(), random).mod(p.subtract(BigInteger.ONE))
				.add(BigInteger.ONE);
		} while (h.modPow(p.subtract(BigInteger.ONE).divide(q), p).equals(BigInteger.ONE));

		return h.modPow(BigInteger.valueOf(2), p);
	}

	/**
	 * Splits a secret into shares using Feldman's VSS scheme.
	 *
	 * @param secretBytes
	 *            the secret to split as byte array
	 * @param threshold
	 *            minimum number of shares needed for reconstruction (t)
	 * @param nShares
	 *            total number of shares to generate (n)
	 * @return result containing shares, commitments, and the original secret
	 * @throws IllegalArgumentException
	 *             if threshold > nShares or threshold < 1
	 */
	public static ShareGenerationResult splitSecret(final byte[] secretBytes, final int threshold,
		final int nShares)
	{
		Objects.requireNonNull(secretBytes);

		if (threshold < 1 || threshold > nShares)
		{
			throw new IllegalArgumentException(
				"Threshold must be between 1 and nShares (inclusive)");
		}

		// Convert secret to BigInteger
		BigInteger secret = new BigInteger(1, secretBytes);

		// Generate primes and generator
		BigInteger[] primes = generateSafePrimes();
		BigInteger p = primes[0];
		BigInteger q = primes[1];
		BigInteger g = findGenerator(p, q);

		// Ensure secret is in range [1, q-1]
		secret = secret.mod(q.subtract(BigInteger.ONE)).add(BigInteger.ONE);

		// Generate random coefficients for the polynomial f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}
		SecureRandom random = new SecureRandom();
		BigInteger[] coefficients = new BigInteger[threshold];
		coefficients[0] = secret; // a_0 = secret

		for (int i = 1; i < threshold; i++)
		{
			coefficients[i] = new BigInteger(q.bitLength(), random).mod(q);
		}

		// Compute commitments C_j = g^{a_j} mod p
		List<BigInteger> commitments = new ArrayList<>(threshold);
		for (int i = 0; i < threshold; i++)
		{
			commitments.add(g.modPow(coefficients[i], p));
		}

		// Generate shares s_i = f(i) mod q for i = 1 to n
		List<Share> shares = new ArrayList<>(nShares);
		for (int i = 1; i <= nShares; i++)
		{
			BigInteger shareValue = BigInteger.ZERO;
			BigInteger x = BigInteger.valueOf(i);

			for (int j = 0; j < threshold; j++)
			{
				BigInteger term = coefficients[j].multiply(x.pow(j)).mod(q);
				shareValue = shareValue.add(term).mod(q);
			}

			shares.add(new Share(i, shareValue));
		}

		Commitments commitObj = new Commitments(commitments, p, q, g);
		return new ShareGenerationResult(shares, commitObj, secret);
	}

	/**
	 * Splits a secret with default parameters.
	 *
	 * @param secretBytes
	 *            the secret to split
	 * @return result containing shares, commitments, and the original secret
	 */
	public static ShareGenerationResult splitSecret(final byte[] secretBytes)
	{
		return splitSecret(secretBytes, DEFAULT_THRESHOLD, DEFAULT_N_SHARES);
	}

	/**
	 * Verifies a share against the commitments.
	 *
	 * @param share
	 *            the share to verify
	 * @param commitments
	 *            the public commitments
	 * @return true if the share is valid, false otherwise
	 */
	public static boolean verifyShare(final Share share, final Commitments commitments)
	{
		Objects.requireNonNull(share);
		Objects.requireNonNull(commitments);

		BigInteger g = commitments.getG();
		BigInteger p = commitments.getP();
		List<BigInteger> commitmentValues = commitments.getValues();
		int t = commitmentValues.size();

		// Compute g^{s_i} mod p
		BigInteger leftSide = g.modPow(share.getValue(), p);

		// Compute ∏_{j=0}^{t-1} (C_j)^{i^j} mod p
		BigInteger rightSide = BigInteger.ONE;
		BigInteger i = BigInteger.valueOf(share.getIndex());

		for (int j = 0; j < t; j++)
		{
			BigInteger exponent = i.pow(j).mod(commitments.getQ());
			BigInteger term = commitmentValues.get(j).modPow(exponent, p);
			rightSide = rightSide.multiply(term).mod(p);
		}

		return leftSide.equals(rightSide);
	}

	/**
	 * Verifies multiple shares against the commitments.
	 *
	 * @param shares
	 *            the shares to verify
	 * @param commitments
	 *            the public commitments
	 * @return list of indices of invalid shares (empty if all valid)
	 */
	public static List<Integer> verifyShares(final List<Share> shares,
		final Commitments commitments)
	{
		List<Integer> invalidIndices = new ArrayList<>();

		for (Share share : shares)
		{
			if (!verifyShare(share, commitments))
			{
				invalidIndices.add(share.getIndex());
			}
		}

		return invalidIndices;
	}

	/**
	 * Reconstructs the secret from verified shares using Lagrange interpolation.
	 *
	 * @param shares
	 *            the shares to use (must be at least threshold)
	 * @param commitments
	 *            the commitments for verification
	 * @param q
	 *            the subgroup order
	 * @return the reconstructed secret
	 * @throws IllegalStateException
	 *             if any share fails verification
	 * @throws IllegalArgumentException
	 *             if insufficient shares provided
	 */
	public static BigInteger reconstructSecret(final List<Share> shares,
		final Commitments commitments, final BigInteger q)
	{
		Objects.requireNonNull(shares);
		Objects.requireNonNull(commitments);
		Objects.requireNonNull(q);

		if (shares.isEmpty())
		{
			throw new IllegalArgumentException("No shares provided");
		}

		// Verify all shares first
		List<Integer> invalidShares = verifyShares(shares, commitments);
		if (!invalidShares.isEmpty())
		{
			throw new IllegalStateException(
				"Invalid shares detected for indices: " + invalidShares);
		}

		// Check minimum threshold
		int t = commitments.getValues().size();
		if (shares.size() < t)
		{
			throw new IllegalArgumentException(String.format(
				"Insufficient shares: need at least %d, got %d", t, shares.size()));
		}

		// Use first t shares for reconstruction
		List<Share> subset = shares.subList(0, Math.min(t, shares.size()));

		// Lagrange interpolation to find f(0) = secret
		BigInteger secret = BigInteger.ZERO;

		for (int i = 0; i < subset.size(); i++)
		{
			Share shareI = subset.get(i);
			BigInteger xi = BigInteger.valueOf(shareI.getIndex());
			BigInteger yi = shareI.getValue();

			// Compute Lagrange basis polynomial L_i(0)
			BigInteger numerator = BigInteger.ONE;
			BigInteger denominator = BigInteger.ONE;

			for (int j = 0; j < subset.size(); j++)
			{
				if (i != j)
				{
					BigInteger xj = BigInteger.valueOf(subset.get(j).getIndex());
					numerator = numerator.multiply(xj.negate()).mod(q);
					denominator = denominator.multiply(xi.subtract(xj)).mod(q);
				}
			}

			// Compute modular inverse of denominator
			BigInteger lagrangeCoeff = numerator.multiply(denominator.modInverse(q)).mod(q);

			// Add contribution: y_i * L_i(0)
			secret = secret.add(yi.multiply(lagrangeCoeff)).mod(q);
		}

		return secret;
	}

	/**
	 * Reconstructs the secret and converts to byte array.
	 *
	 * @param shares
	 *            the shares to use
	 * @param commitments
	 *            the commitments for verification
	 * @param q
	 *            the subgroup order
	 * @param expectedLength
	 *            expected byte array length
	 * @return the reconstructed secret as byte array
	 */
	public static byte[] reconstructSecretBytes(final List<Share> shares,
		final Commitments commitments, final BigInteger q, final int expectedLength)
	{
		BigInteger secret = reconstructSecret(shares, commitments, q);
		byte[] bytes = secret.toByteArray();

		// Handle leading zero byte from BigInteger
		if (bytes.length > expectedLength && bytes[0] == 0)
		{
			bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
		}

		// Pad or truncate to expected length
		if (bytes.length < expectedLength)
		{
			byte[] padded = new byte[expectedLength];
			System.arraycopy(bytes, 0, padded, expectedLength - bytes.length, bytes.length);
			return padded;
		}
		else if (bytes.length > expectedLength)
		{
			return Arrays.copyOfRange(bytes, bytes.length - expectedLength, bytes.length);
		}

		return bytes;
	}

	/**
	 * Converts a byte array to a fixed-length representation suitable for secret sharing.
	 *
	 * @param data
	 *            the data to convert
	 * @param bitLength
	 *            desired bit length (must be multiple of 8)
	 * @return BigInteger representation
	 */
	public static BigInteger toBigInteger(final byte[] data, final int bitLength)
	{
		Objects.requireNonNull(data);

		if (bitLength % 8 != 0)
		{
			throw new IllegalArgumentException("Bit length must be multiple of 8");
		}

		int byteLength = bitLength / 8;
		byte[] padded = new byte[byteLength];

		int start = Math.max(0, data.length - byteLength);
		int copyLength = Math.min(data.length, byteLength);

		System.arraycopy(data, start, padded, byteLength - copyLength, copyLength);

		return new BigInteger(1, padded);
	}
}
