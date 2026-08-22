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
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;

/**
 * The class {@link SRP6aServer} implements the server side of the SRP-6a protocol.
 * 
 * <p>
 * SRP-6a (Secure Remote Password protocol version 6a) allows a client to authenticate to a server
 * using a password without transmitting the password itself. This class handles the server's role
 * in the key exchange and authentication process.
 *
 * <p>
 * Protocol flow:
 * <ol>
 * <li>Client sends identity (I) to server</li>
 * <li>Server responds with salt (s) and public value B = k*v + g^b mod N</li>
 * <li>Client computes A = g^a mod N, sends A to server</li>
 * <li>Both compute session key K</li>
 * <li>Client sends proof M1 = H(A | B | K)</li>
 * <li>Server verifies M1 and responds with M2 = H(A | M1 | K)</li>
 * </ol>
 *
 * @author Asterios Raptis
 */
public final class SRP6aServer
{

	private final BigInteger n;
	private final BigInteger g;
	private final String hashAlgorithm;
	private final SecureRandom random;
	private final Digest digest;
	private BigInteger b;
	private BigInteger B;
	private BigInteger verifier;
	private BigInteger clientPublicKey;
	private BigInteger S;

	/**
	 * Constructs a new SRP-6a server with default parameters.
	 */
	public SRP6aServer()
	{
		this(SRP6aVerifierGenerator.DEFAULT_N, SRP6aVerifierGenerator.DEFAULT_G,
			SRP6aVerifierGenerator.DEFAULT_HASH_ALGORITHM);
	}

	/**
	 * Constructs a new SRP-6a server with specified parameters.
	 *
	 * @param n
	 *            the prime modulus
	 * @param g
	 *            the generator
	 * @param hashAlgorithm
	 *            the hash algorithm to use
	 */
	public SRP6aServer(final BigInteger n, final BigInteger g, final String hashAlgorithm)
	{
		if (n == null || g == null || hashAlgorithm == null)
		{
			throw new IllegalArgumentException("Parameters cannot be null");
		}
		this.n = n;
		this.g = g;
		this.hashAlgorithm = hashAlgorithm;
		this.random = new SecureRandom();
		this.digest = SrpDigests.newDigest(hashAlgorithm);
	}

	/**
	 * Sets the verifier for the user.
	 *
	 * @param verifier
	 *            the precomputed verifier v = g^x mod N
	 * @throws IllegalArgumentException
	 *             if verifier is null
	 */
	public void setVerifier(final BigInteger verifier)
	{
		if (verifier == null)
		{
			throw new IllegalArgumentException("Verifier cannot be null");
		}
		this.verifier = verifier;
	}

	/**
	 * Generates the server's public value B = k*v + g^b mod N.
	 *
	 * @return the public value B
	 * @throws IllegalStateException
	 *             if verifier is not set
	 */
	public BigInteger generatePublicValue()
	{
		if (verifier == null)
		{
			throw new IllegalStateException("Verifier not set");
		}

		// Generate random private value b
		this.b = SRP6Util.generatePrivateValue(digest, n, g, random);

		// Compute k = H(N | g)
		final BigInteger k = SRP6Util.calculateK(digest, n, g);

		// Compute B = k*v + g^b mod N
		final BigInteger kv = k.multiply(verifier).mod(n);
		final BigInteger gb = g.modPow(b, n);
		this.B = kv.add(gb).mod(n);

		return B;
	}

	/**
	 * Sets the client's public value A.
	 *
	 * @param clientPublicKey
	 *            the client's public value A
	 * @throws IllegalArgumentException
	 *             if clientPublicKey is null
	 * @throws SecurityException
	 *             if clientPublicKey mod N is zero - the classic SRP zero-key attack, where a
	 *             malicious client tries to force a session key that does not depend on the
	 *             password, bypassing authentication entirely (see RFC 5054 section 2.5.4)
	 */
	public void setClientPublicKey(final BigInteger clientPublicKey)
	{
		if (clientPublicKey == null)
		{
			throw new IllegalArgumentException("Client public key cannot be null");
		}
		try
		{
			this.clientPublicKey = SRP6Util.validatePublicValue(n, clientPublicKey);
		}
		catch (final CryptoException e)
		{
			throw new SecurityException("Invalid client public value", e);
		}
	}

	/**
	 * Computes the session key K based on the client's public value.
	 *
	 * @return the session key K
	 * @throws IllegalStateException
	 *             if verifier or client public key is not set
	 */
	public BigInteger computeSessionKey()
	{
		if (verifier == null)
		{
			throw new IllegalStateException("Verifier not set");
		}
		if (clientPublicKey == null)
		{
			throw new IllegalStateException("Client public key not set");
		}

		// Compute u = H(A | B)
		final BigInteger u = SRP6Util.calculateU(digest, n, clientPublicKey, B);

		// Compute S = (A * v^u)^b mod N - same formula BC's own SRP6Server.calculateS() uses
		final BigInteger vu = verifier.modPow(u, n);
		final BigInteger Avu = clientPublicKey.multiply(vu).mod(n);
		this.S = Avu.modPow(b, n);

		// Compute K = H(S)
		return SRP6Util.calculateKey(digest, n, S);
	}

	/**
	 * Computes the server's proof M2 = H(A | M1 | K).
	 *
	 * @param clientProof
	 *            the client's proof M1
	 * @param sessionKey
	 *            the session key K
	 * @return the proof M2
	 * @throws IllegalArgumentException
	 *             if clientProof or sessionKey is null
	 */
	public BigInteger computeServerProof(final BigInteger clientProof, final BigInteger sessionKey)
	{
		if (clientProof == null)
		{
			throw new IllegalArgumentException("Client proof cannot be null");
		}
		if (sessionKey == null)
		{
			throw new IllegalArgumentException("Session key cannot be null");
		}
		if (clientPublicKey == null)
		{
			throw new IllegalArgumentException("Client public key not set");
		}
		if (S == null)
		{
			throw new IllegalArgumentException("Session not established");
		}

		return SRP6Util.calculateM2(digest, n, clientPublicKey, clientProof, S);
	}

	/**
	 * Verifies the client's proof M1.
	 *
	 * @param clientProof
	 *            the client's proof M1
	 * @param sessionKey
	 *            the session key K
	 * @return true if the client proof is valid, false otherwise
	 */
	public boolean verifyClientProof(final BigInteger clientProof, final BigInteger sessionKey)
	{
		if (clientProof == null || sessionKey == null)
		{
			return false;
		}
		if (B == null)
		{
			return false;
		}

		if (S == null)
		{
			return false;
		}

		// Expected M1 = H(A | B | S)
		final BigInteger expectedM1 = SRP6Util.calculateM1(digest, n, clientPublicKey, B, S);
		return expectedM1.equals(clientProof);
	}

	/**
	 * Gets the server's public value B.
	 *
	 * @return the public value B
	 */
	public BigInteger getPublicValue()
	{
		return B;
	}

}
