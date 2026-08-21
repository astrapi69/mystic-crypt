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
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.agreement.srp.SRP6StandardGroups;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;

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

	/** Default prime N (RFC 5054 1024-bit group), reusing Bouncy Castle's own verified constant */
	public static final BigInteger DEFAULT_N = SRP6StandardGroups.rfc5054_1024.getN();

	/** Default generator g */
	public static final BigInteger DEFAULT_G = SRP6StandardGroups.rfc5054_1024.getG();

	/** Default hash algorithm */
	public static final String DEFAULT_HASH_ALGORITHM = "SHA-256";

	private final BigInteger n;
	private final BigInteger g;
	private final String hashAlgorithm;
	private final SecureRandom random;
	private final SRP6VerifierGenerator bcGenerator;

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
		this.bcGenerator = new SRP6VerifierGenerator();
		this.bcGenerator.init(n, g, SrpDigests.newDigest(hashAlgorithm));
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

		final byte[] passwordBytes = new String(password).getBytes(StandardCharsets.UTF_8);
		try
		{
			// v = g^x mod N, x = H(s | H(I | ":" | P)) - both computed by SRP6VerifierGenerator
			// via SRP6Util.calculateX, which pads correctly per RFC 5054
			return bcGenerator.generateVerifier(salt, identity.getBytes(StandardCharsets.UTF_8),
				passwordBytes);
		}
		finally
		{
			Arrays.fill(password, '\0');
			Arrays.fill(passwordBytes, (byte)0);
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
