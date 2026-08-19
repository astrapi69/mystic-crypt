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
package io.github.astrapi69.mystic.crypt.key;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Objects;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.factory.SignatureFactory;

/**
 * The class {@link SlhDsaVerifier} verifies signatures produced by {@link SlhDsaSigner} with an
 * SLH-DSA public key. Requires Bouncy Castle registered as a security provider (
 * {@code Security.addProvider(new BouncyCastleProvider())}), since SLH-DSA is not natively
 * supported by the JDK.
 */
public class SlhDsaVerifier
{

	/** The public key. */
	private final PublicKey publicKey;

	/** The SLH-DSA parameter set, e.g. "SLH-DSA-SHA2-128S". */
	private final String algorithm;

	/**
	 * Instantiates a new {@link SlhDsaVerifier} with the given public key.
	 *
	 * @param publicKey
	 *            the public key, must be an SLH-DSA key
	 * @param algorithm
	 *            one of the {@code SLH_DSA_*} constants in {@link KeyPairGeneratorAlgorithm} - must
	 *            match the algorithm the key pair was generated with
	 */
	public SlhDsaVerifier(final PublicKey publicKey, final KeyPairGeneratorAlgorithm algorithm)
	{
		this.publicKey = Objects.requireNonNull(publicKey);
		this.algorithm = SlhDsaSigner.requireSlhDsa(algorithm).getAlgorithm();
	}

	/**
	 * Verifies the given signature over the given data.
	 *
	 * @param data
	 *            the data that was signed
	 * @param signature
	 *            the signature to verify
	 * @return true if the signature is valid for the given data and public key, false if it is
	 *         invalid or malformed
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the {@link java.security.Signature} object fails
	 * @throws InvalidKeyException
	 *             is thrown if the public key is invalid for the configured algorithm
	 */
	public boolean verify(final byte[] data, final byte[] signature)
		throws NoSuchAlgorithmException, InvalidKeyException
	{
		return SignatureFactory.verify(publicKey, algorithm, data, signature);
	}

}
