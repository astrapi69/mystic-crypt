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
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import io.github.astrapi69.crypt.api.algorithm.AesAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.key.KeyAgreementAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.factory.HkdfExtensions;
import io.github.astrapi69.crypt.data.factory.KeyAgreementFactory;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;

/**
 * The class {@link X25519KeyExchange} derives a shared AES key from an X25519 key pair exchange.
 * X25519 is natively supported by the JDK (since JDK 11) - no Bouncy Castle involved.
 *
 * <p>
 * The raw X25519 shared secret (32 bytes) is passed through HKDF ({@link HkdfExtensions}) rather
 * than used directly, since it isn't itself a uniformly random key suitable for direct use as one.
 * The resulting {@link SecretKey} can be used directly with e.g.
 * {@link io.github.astrapi69.mystic.crypt.base.BaseByteArrayEncryptor}/
 * {@link io.github.astrapi69.mystic.crypt.base.BaseByteArrayDecryptor}.
 */
public final class X25519KeyExchange
{

	private X25519KeyExchange()
	{
	}

	/**
	 * Generates a new X25519 {@link KeyPair}.
	 *
	 * @return the new key pair
	 * @throws NoSuchAlgorithmException
	 *             is thrown if the X25519 algorithm is not available
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	public static KeyPair newKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException
	{
		return KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.X25519);
	}

	/**
	 * Derives a shared AES {@link SecretKey} of the given length from the given private and public
	 * key via X25519 key agreement followed by HKDF key derivation.
	 *
	 * @param privateKey
	 *            this party's X25519 private key
	 * @param publicKey
	 *            the other party's X25519 public key
	 * @param keyLengthBytes
	 *            the desired length in bytes of the derived key (e.g. 32 for AES-256)
	 * @return the derived shared {@link SecretKey}
	 * @throws InvalidKeyException
	 *             is thrown if either key is invalid for X25519 key agreement
	 * @throws NoSuchAlgorithmException
	 *             is thrown if the X25519 key agreement algorithm is not available
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 */
	public static SecretKey deriveSharedSecret(final PrivateKey privateKey,
		final PublicKey publicKey, final int keyLengthBytes)
		throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException
	{
		final byte[] rawSharedSecret = KeyAgreementFactory.newSharedSecret(privateKey, publicKey,
			KeyAgreementAlgorithm.X25519.getAlgorithm(), null, true);
		try
		{
			final byte[] derivedKeyBytes = HkdfExtensions.deriveKey(rawSharedSecret, null, null,
				keyLengthBytes);
			return new SecretKeySpec(derivedKeyBytes, AesAlgorithm.AES.getAlgorithm());
		}
		finally
		{
			Arrays.fill(rawSharedSecret, (byte)0);
		}
	}

}
