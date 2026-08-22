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
 * The class {@link Ed25519Signer} signs byte arrays with an Ed25519 private key. Ed25519 is
 * natively supported by the JDK (since JDK 15) - no Bouncy Castle involved. The pendant class
 * {@link Ed25519Verifier} verifies signatures produced by this class.
 */
public class Ed25519Signer
{

	/** The private key. */
	private final PrivateKey privateKey;

	/**
	 * Instantiates a new {@link Ed25519Signer} with the given private key.
	 *
	 * @param privateKey
	 *            the private key, must be an Ed25519 key
	 */
	public Ed25519Signer(final PrivateKey privateKey)
	{
		this.privateKey = Objects.requireNonNull(privateKey);
	}

	/**
	 * Generates a new Ed25519 {@link KeyPair}.
	 *
	 * @return the new key pair
	 * @throws NoSuchAlgorithmException
	 *             is thrown if the Ed25519 algorithm is not available
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	public static KeyPair newKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException
	{
		return KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.Ed25519);
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
	 *             is thrown if the private key is invalid for Ed25519
	 * @throws SignatureException
	 *             is thrown if the {@link java.security.Signature} object is not properly
	 *             initialized
	 */
	public byte[] sign(final byte[] data)
		throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
	{
		return SignatureFactory.sign(privateKey, KeyPairGeneratorAlgorithm.Ed25519.getAlgorithm(),
			data);
	}

}
