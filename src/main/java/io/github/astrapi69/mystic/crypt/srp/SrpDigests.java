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

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.util.DigestFactory;

/**
 * Maps a JCA digest algorithm name to a fresh Bouncy Castle {@link Digest} instance, for the SRP-6a
 * classes in this package (which need a BC {@link Digest}, not a
 * {@link java.security.MessageDigest}, since they delegate to
 * {@link org.bouncycastle.crypto.agreement.srp.SRP6Util}).
 */
final class SrpDigests
{

	private SrpDigests()
	{
	}

	/**
	 * Creates a fresh {@link Digest} instance for the given JCA algorithm name. A new instance is
	 * returned on every call since {@link Digest} is stateful.
	 *
	 * @param algorithm
	 *            the JCA digest algorithm name (e.g. {@code "SHA-256"})
	 * @return a fresh digest instance
	 * @throws IllegalArgumentException
	 *             if the algorithm is not one of the supported names
	 */
	static Digest newDigest(final String algorithm)
	{
		switch (algorithm)
		{
			case "SHA-1" :
				return DigestFactory.createSHA1();
			case "SHA-224" :
				return DigestFactory.createSHA224();
			case "SHA-256" :
				return DigestFactory.createSHA256();
			case "SHA-384" :
				return DigestFactory.createSHA384();
			case "SHA-512" :
				return DigestFactory.createSHA512();
			case "SHA3-256" :
				return DigestFactory.createSHA3_256();
			default :
				throw new IllegalArgumentException("Unsupported hash algorithm: " + algorithm);
		}
	}

}
