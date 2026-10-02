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
package io.github.astrapi69.mystic.crypt.mac;

import java.security.GeneralSecurityException;
import java.util.Objects;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import io.github.astrapi69.crypt.api.algorithm.MacAlgorithm;

/**
 * HMAC as one call (#163), on the platform's {@link Mac} - nothing is computed here but the call.
 * <p>
 * Every place in this library that needs an HMAC goes through this class, so a missing algorithm is
 * refused one way, with its name, instead of as a checked exception each caller wraps differently.
 */
public final class HmacExtensions
{

	/** The prefix every raw-key HMAC of {@link MacAlgorithm} carries in its algorithm name */
	private static final String HMAC_PREFIX = "Hmac";

	private HmacExtensions()
	{
	}

	/**
	 * Computes an HMAC
	 *
	 * @param algorithm
	 *            the HMAC algorithm, e.g. {@link MacAlgorithm#HmacSHA512}
	 * @param key
	 *            the key; any length, a key longer than the hash block is hashed first as HMAC
	 *            prescribes (RFC 2104)
	 * @param message
	 *            the message
	 * @return the authentication code
	 * @throws IllegalArgumentException
	 *             for an empty key, which would authenticate nothing
	 * @throws IllegalArgumentException
	 *             for a value that is no HMAC over a raw key: {@link MacAlgorithm#UNKNOWN} and the
	 *             password based {@code PBEWith...} values
	 * @throws IllegalStateException
	 *             when the Java runtime lacks the algorithm
	 */
	public static byte[] hmac(final MacAlgorithm algorithm, final byte[] key, final byte[] message)
	{
		Objects.requireNonNull(algorithm);
		Objects.requireNonNull(message);
		if (!algorithm.getAlgorithm().startsWith(HMAC_PREFIX))
		{
			// decided here and not left to the provider: with Bouncy Castle registered a PBE
			// variant accepts raw key bytes and computes something, without it the JDK refuses
			throw new IllegalArgumentException(
				algorithm + " is no HMAC over a raw key; use one of the Hmac values");
		}
		if (key.length == 0)
		{
			throw new IllegalArgumentException(
				"an HMAC key of 0 bytes authenticates nothing; " + algorithm + " needs a key");
		}
		try
		{
			Mac mac = Mac.getInstance(algorithm.getAlgorithm());
			mac.init(new SecretKeySpec(key, algorithm.getAlgorithm()));
			return mac.doFinal(message);
		}
		catch (GeneralSecurityException missing)
		{
			// every Hmac value of MacAlgorithm is in the JDK, so this is a stripped-down runtime
			throw new IllegalStateException("this Java runtime cannot compute " + algorithm,
				missing);
		}
	}
}
