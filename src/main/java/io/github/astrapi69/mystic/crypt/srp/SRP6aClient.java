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

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.srp.SRP6Util;

/**
 * The class {@link SRP6aClient} implements the client side of the SRP-6a protocol.
 * 
 * <p>
 * SRP-6a (Secure Remote Password protocol version 6a) allows a client to authenticate to a server
 * using a password without transmitting the password itself. This class handles the client's role
 * in the key exchange and authentication process.
 *
 * <p>
 * Protocol flow:
 * <ol>
 * <li>Client sends identity (I) to server</li>
 * <li>Server responds with salt (s) and public value (B)</li>
 * <li>Client computes A = g^a mod N, sends A to server</li>
 * <li>Both compute session key K</li>
 * <li>Client sends proof M1 = H(A | B | K)</li>
 * <li>Server verifies and responds with M2</li>
 * </ol>
 *
 * @author Asterios Raptis
 */
public final class SRP6aClient
{

	private final BigInteger n;
	private final BigInteger g;
	private final String hashAlgorithm;
	private final SecureRandom random;
	private final Digest digest;
	private BigInteger a;
	private BigInteger A;
	private byte[] salt;
	private BigInteger serverPublicKey;
	private BigInteger S;

	/**
	 * Constructs a new SRP-6a client with default parameters.
	 */
	public SRP6aClient()
	{
		this(SRP6aVerifierGenerator.DEFAULT_N, SRP6aVerifierGenerator.DEFAULT_G,
			SRP6aVerifierGenerator.DEFAULT_HASH_ALGORITHM);
	}

	/**
	 * Constructs a new SRP-6a client with specified parameters.
	 *
	 * @param n
	 *            the prime modulus
	 * @param g
	 *            the generator
	 * @param hashAlgorithm
	 *            the hash algorithm to use
	 */
	public SRP6aClient(final BigInteger n, final BigInteger g, final String hashAlgorithm)
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
	 * Generates the client's public value A = g^a mod N.
	 *
	 * @return the public value A
	 */
	public BigInteger generatePublicValue()
	{
		// Generate random private value a
		this.a = SRP6Util.generatePrivateValue(digest, n, g, random);

		// Compute A = g^a mod N
		this.A = g.modPow(a, n);

		return A;
	}

	/**
	 * Sets the server's salt and public value B.
	 *
	 * @param salt
	 *            the salt from the server
	 * @param serverPublicKey
	 *            the server's public value B
	 * @throws IllegalArgumentException
	 *             if salt or serverPublicKey is null
	 * @throws SecurityException
	 *             if serverPublicKey mod N is zero - the classic SRP zero-key attack, where a
	 *             malicious or compromised server tries to force a session key that does not depend
	 *             on the password (see RFC 5054 section 2.5.4)
	 */
	public void setServerCredentials(final byte[] salt, final BigInteger serverPublicKey)
	{
		if (salt == null)
		{
			throw new IllegalArgumentException("Salt cannot be null");
		}
		if (serverPublicKey == null)
		{
			throw new IllegalArgumentException("Server public key cannot be null");
		}
		this.salt = salt;
		try
		{
			this.serverPublicKey = SRP6Util.validatePublicValue(n, serverPublicKey);
		}
		catch (final CryptoException e)
		{
			throw new SecurityException("Invalid server public value", e);
		}
	}

	/**
	 * Computes the session key K based on the password.
	 *
	 * @param identity
	 *            the user identity (username)
	 * @param password
	 *            the password
	 * @return the session key K
	 * @throws IllegalArgumentException
	 *             if identity or password is null, or if server credentials are not set
	 */
	public BigInteger computeSessionKey(final String identity, final char[] password)
	{
		if (identity == null)
		{
			throw new IllegalArgumentException("Identity cannot be null");
		}
		if (password == null)
		{
			throw new IllegalArgumentException("Password cannot be null");
		}
		if (salt == null || serverPublicKey == null)
		{
			throw new IllegalArgumentException("Server credentials not set");
		}

		final byte[] passwordBytes = new String(password).getBytes(StandardCharsets.UTF_8);
		try
		{
			// Compute u = H(A | B)
			final BigInteger u = SRP6Util.calculateU(digest, n, A, serverPublicKey);

			// Compute x = H(s | H(I | ":" | P))
			final BigInteger x = SRP6Util.calculateX(digest, n, salt,
				identity.getBytes(StandardCharsets.UTF_8), passwordBytes);

			// Compute S = (B - k * g^x)^(a + u * x) mod N, where k = H(N | g) - same formula BC's
			// own SRP6Client.calculateS() uses
			final BigInteger k = SRP6Util.calculateK(digest, n, g);
			final BigInteger gx = g.modPow(x, n);
			final BigInteger kgx = k.multiply(gx).mod(n);
			final BigInteger base = serverPublicKey.subtract(kgx).mod(n);
			final BigInteger ux = u.multiply(x);
			final BigInteger exponent = a.add(ux);
			this.S = base.modPow(exponent, n);

			// Compute K = H(S)
			return SRP6Util.calculateKey(digest, n, S);
		}
		finally
		{
			Arrays.fill(password, '\0');
			Arrays.fill(passwordBytes, (byte)0);
		}
	}

	/**
	 * Computes the client's proof M1 = H(A | B | K).
	 *
	 * @param sessionKey
	 *            the session key K, as returned by {@link #computeSessionKey(String, char[])}; only
	 *            checked for presence - the actual M1 computation uses the raw shared secret S
	 *            computed internally by {@link #computeSessionKey(String, char[])}, per RFC 5054
	 * @return the proof M1
	 * @throws IllegalArgumentException
	 *             if sessionKey is null or server credentials are not set
	 */
	public BigInteger computeProof(final BigInteger sessionKey)
	{
		if (sessionKey == null)
		{
			throw new IllegalArgumentException("Session key cannot be null");
		}
		if (A == null || serverPublicKey == null || S == null)
		{
			throw new IllegalArgumentException("Credentials not set");
		}

		return SRP6Util.calculateM1(digest, n, A, serverPublicKey, S);
	}

	/**
	 * Verifies the server's proof M2.
	 *
	 * @param serverProof
	 *            the server's proof M2
	 * @param sessionKey
	 *            the session key K
	 * @return true if the server proof is valid, false otherwise
	 */
	public boolean verifyServerProof(final BigInteger serverProof, final BigInteger sessionKey)
	{
		if (serverProof == null || sessionKey == null)
		{
			return false;
		}

		try
		{
			// Expected M2 = H(A | M1 | S)
			final BigInteger clientProof = computeProof(sessionKey);
			final BigInteger expectedM2 = SRP6Util.calculateM2(digest, n, A, clientProof, S);
			return expectedM2.equals(serverProof);
		}
		catch (final Exception e)
		{
			return false;
		}
	}

	/**
	 * Gets the client's public value A.
	 *
	 * @return the public value A
	 */
	public BigInteger getPublicValue()
	{
		return A;
	}

}
