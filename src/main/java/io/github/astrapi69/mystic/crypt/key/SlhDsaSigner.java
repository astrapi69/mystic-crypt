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
package io.github.astrapi69.mystic.crypt.key;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.util.Objects;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.factory.SignatureFactory;

/**
 * The class {@link SlhDsaSigner} signs byte arrays with an SLH-DSA private key. SLH-DSA is the
 * NIST-standardized (FIPS 205) hash-based post-quantum signature algorithm - conservative, relying
 * only on the security of its underlying hash function, at the cost of large signatures (tens of
 * KB) and, for the "S" (small-signature) parameter sets, slow signing. Requires Bouncy Castle
 * registered as a security provider ({@code Security.addProvider(new
 * BouncyCastleProvider())}), since SLH-DSA is not natively supported by the JDK. The pendant class
 * {@link SlhDsaVerifier} verifies signatures produced by this class.
 */
public class SlhDsaSigner
{

	/** The private key. */
	private final PrivateKey privateKey;

	/** The SLH-DSA parameter set, e.g. "SLH-DSA-SHA2-128S". */
	private final String algorithm;

	/**
	 * Instantiates a new {@link SlhDsaSigner} with the given private key.
	 *
	 * @param privateKey
	 *            the private key, must be an SLH-DSA key
	 * @param algorithm
	 *            one of the {@code SLH_DSA_*} constants in {@link KeyPairGeneratorAlgorithm} - must
	 *            match the algorithm the key pair was generated with
	 */
	public SlhDsaSigner(final PrivateKey privateKey, final KeyPairGeneratorAlgorithm algorithm)
	{
		this.privateKey = Objects.requireNonNull(privateKey);
		this.algorithm = requireSlhDsa(algorithm).getAlgorithm();
	}

	/**
	 * Generates a new SLH-DSA {@link KeyPair} for the given parameter set.
	 *
	 * @param algorithm
	 *            one of the {@code SLH_DSA_*} constants in {@link KeyPairGeneratorAlgorithm}
	 * @return the new key pair
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no provider supports the given algorithm
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	public static KeyPair newKeyPair(final KeyPairGeneratorAlgorithm algorithm)
		throws NoSuchAlgorithmException, NoSuchProviderException
	{
		requireSlhDsa(algorithm);
		return KeyPairFactory.newKeyPair(algorithm);
	}

	/**
	 * Signs the given data.
	 *
	 * @param data
	 *            the data to sign
	 * @return the signature
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the {@link java.security.Signature} object fails
	 * @throws InvalidKeyException
	 *             is thrown if the private key is invalid for the configured algorithm
	 * @throws SignatureException
	 *             is thrown if the {@link java.security.Signature} object is not properly
	 *             initialized
	 */
	public byte[] sign(final byte[] data)
		throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
	{
		return SignatureFactory.sign(privateKey, algorithm, data);
	}

	static KeyPairGeneratorAlgorithm requireSlhDsa(final KeyPairGeneratorAlgorithm algorithm)
	{
		Objects.requireNonNull(algorithm);
		if (!algorithm.name().startsWith("SLH_DSA_"))
		{
			throw new IllegalArgumentException(
				"algorithm must be one of the SLH_DSA_* constants but was " + algorithm);
		}
		return algorithm;
	}

}
