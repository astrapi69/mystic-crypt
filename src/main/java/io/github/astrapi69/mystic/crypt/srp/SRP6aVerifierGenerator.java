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
package io.github.astrapi69.mystic.crypt.srp;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * The class {@link SRP6aVerifierGenerator} generates SRP-6a password verifiers.
 * 
 * <p>
 * SRP-6a (Secure Remote Password protocol version 6a) is a cryptographic protocol for
 * password-authenticated key exchange. It allows a client to authenticate to a server using a
 * password without sending the password itself over the network.
 * </p>
 * 
 * <p>
 * The verifier is computed as: v = g^x mod N, where x = H(s | H(I | ":" | P))
 * </p>
 * 
 * @author Asterios Raptis
 */
public final class SRP6aVerifierGenerator
{

	/** Default prime N (RFC 5054 1024-bit group) */
	public static final BigInteger DEFAULT_N = new BigInteger(
		"EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3");

	/** Default generator g */
	public static final BigInteger DEFAULT_G = BigInteger.valueOf(2);

	/** Default hash algorithm */
	public static final String DEFAULT_HASH_ALGORITHM = "SHA-256";

	private final BigInteger n;
	private final BigInteger g;
	private final String hashAlgorithm;
	private final SecureRandom random;

	/**
	 * Constructs a new verifier generator with default parameters.
	 */
	public SRP6aVerifierGenerator()
	{
		this(DEFAULT_N, DEFAULT_G, DEFAULT_HASH_ALGORITHM);
	}

	/**
	 * Constructs a new verifier generator with specified parameters.
	 *
	 * @param n
	 *            the prime modulus
	 * @param g
	 *            the generator
	 * @param hashAlgorithm
	 *            the hash algorithm to use
	 */
	public SRP6aVerifierGenerator(final BigInteger n, final BigInteger g,
		final String hashAlgorithm)
	{
		if (n == null || g == null || hashAlgorithm == null)
		{
			throw new IllegalArgumentException("Parameters cannot be null");
		}
		this.n = n;
		this.g = g;
		this.hashAlgorithm = hashAlgorithm;
		this.random = new SecureRandom();
	}

	/**
	 * Generates a new salt.
	 *
	 * @return the salt as a byte array
	 */
	public byte[] generateSalt()
	{
		final byte[] salt = new byte[16];
		random.nextBytes(salt);
		return salt;
	}

	/**
	 * Generates a verifier for the given identity and password.
	 *
	 * @param identity
	 *            the user identity (username)
	 * @param password
	 *            the password
	 * @param salt
	 *            the salt
	 * @return the verifier
	 * @throws IllegalArgumentException
	 *             if any parameter is null
	 */
	public BigInteger generateVerifier(final String identity, final char[] password,
		final byte[] salt)
	{
		if (identity == null)
		{
			throw new IllegalArgumentException("Identity cannot be null");
		}
		if (password == null)
		{
			throw new IllegalArgumentException("Password cannot be null");
		}
		if (salt == null)
		{
			throw new IllegalArgumentException("Salt cannot be null");
		}

		try
		{
			// x = H(s | H(I | ":" | P))
			final byte[] x = computeX(identity, password, salt);
			final BigInteger bigX = new BigInteger(1, x);

			// v = g^x mod N
			return g.modPow(bigX, n);
		}
		finally
		{
			Arrays.fill(password, '\0');
		}
	}

	/**
	 * Computes x = H(s | H(I | ":" | P)).
	 *
	 * @param identity
	 *            the user identity
	 * @param password
	 *            the password
	 * @param salt
	 *            the salt
	 * @return the x value as a byte array
	 */
	private byte[] computeX(final String identity, final char[] password, final byte[] salt)
	{
		try
		{
			final MessageDigest md = MessageDigest.getInstance(hashAlgorithm);

			// Compute H(I | ":" | P)
			final String identityColonPassword = identity + ":" + new String(password);
			byte[] innerHash = md.digest(identityColonPassword.getBytes());

			// Compute H(s | H(I | ":" | P))
			md.update(salt);
			return md.digest(innerHash);
		}
		catch (final NoSuchAlgorithmException e)
		{
			throw new RuntimeException("Hash algorithm not available: " + hashAlgorithm, e);
		}
	}

	/**
	 * Gets the prime modulus N.
	 *
	 * @return the prime modulus
	 */
	public BigInteger getN()
	{
		return n;
	}

	/**
	 * Gets the generator g.
	 *
	 * @return the generator
	 */
	public BigInteger getG()
	{
		return g;
	}

	/**
	 * Gets the hash algorithm.
	 *
	 * @return the hash algorithm
	 */
	public String getHashAlgorithm()
	{
		return hashAlgorithm;
	}

}
