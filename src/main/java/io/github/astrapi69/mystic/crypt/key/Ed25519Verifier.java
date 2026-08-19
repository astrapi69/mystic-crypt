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
 * The class {@link Ed25519Verifier} verifies signatures produced by {@link Ed25519Signer} with an
 * Ed25519 public key.
 */
public class Ed25519Verifier
{

	/** The public key. */
	private final PublicKey publicKey;

	/**
	 * Instantiates a new {@link Ed25519Verifier} with the given public key.
	 *
	 * @param publicKey
	 *            the public key, must be an Ed25519 key
	 */
	public Ed25519Verifier(final PublicKey publicKey)
	{
		this.publicKey = Objects.requireNonNull(publicKey);
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
	 *             is thrown if the public key is invalid for Ed25519
	 */
	public boolean verify(final byte[] data, final byte[] signature)
		throws NoSuchAlgorithmException, InvalidKeyException
	{
		return SignatureFactory.verify(publicKey, KeyPairGeneratorAlgorithm.Ed25519.getAlgorithm(),
			data, signature);
	}

}
