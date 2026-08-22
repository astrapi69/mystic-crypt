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
import java.util.Objects;

import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.SecretKey;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.factory.KemFactory;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;

/**
 * The class {@link MlKemKeyExchange} establishes a shared {@link SecretKey} with ML-KEM, the
 * NIST-standardized (FIPS 203) post-quantum key encapsulation mechanism. Requires Bouncy Castle
 * registered as a security provider ({@code Security.addProvider(new BouncyCastleProvider())}),
 * since ML-KEM is not natively supported by the JDK.
 * <p>
 * Unlike Diffie-Hellman-style key agreement (see {@link X25519KeyExchange}), a KEM is
 * one-directional: only the recipient needs a key pair. The sender calls
 * {@link #encapsulate(PublicKey, KeyPairGeneratorAlgorithm)} with just the recipient's public key,
 * obtaining both the shared secret and a ciphertext to send; the recipient recovers the same shared
 * secret with {@link #decapsulate(PrivateKey, byte[], KeyPairGeneratorAlgorithm)}. The shared
 * secret produced is already a uniformly random key of the correct length for its security level
 * (32 bytes for ML-KEM-768, matching AES-256) - no additional HKDF step is needed before using it
 * directly with e.g. {@link io.github.astrapi69.mystic.crypt.base.BaseByteArrayEncryptor}.
 */
public final class MlKemKeyExchange
{

	private MlKemKeyExchange()
	{
	}

	/**
	 * Generates a new ML-KEM {@link KeyPair} for the given parameter set.
	 *
	 * @param algorithm
	 *            one of {@link KeyPairGeneratorAlgorithm#ML_KEM_512},
	 *            {@link KeyPairGeneratorAlgorithm#ML_KEM_768} or
	 *            {@link KeyPairGeneratorAlgorithm#ML_KEM_1024}
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
		requireMlKem(algorithm);
		return KeyPairFactory.newKeyPair(algorithm);
	}

	/**
	 * Encapsulates a fresh shared secret for the given recipient public key.
	 *
	 * @param recipientPublicKey
	 *            the recipient's ML-KEM public key
	 * @param algorithm
	 *            one of {@link KeyPairGeneratorAlgorithm#ML_KEM_512},
	 *            {@link KeyPairGeneratorAlgorithm#ML_KEM_768} or
	 *            {@link KeyPairGeneratorAlgorithm#ML_KEM_1024} - must match the algorithm the
	 *            recipient's key pair was generated with
	 * @return the shared secret together with the ciphertext to send to the recipient
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no provider supports the given algorithm
	 * @throws InvalidKeyException
	 *             is thrown if the given public key is invalid for the given algorithm
	 */
	public static Encapsulation encapsulate(final PublicKey recipientPublicKey,
		final KeyPairGeneratorAlgorithm algorithm)
		throws NoSuchAlgorithmException, InvalidKeyException
	{
		requireMlKem(algorithm);
		final KEM.Encapsulated encapsulated = KemFactory.encapsulate(recipientPublicKey,
			algorithm.getAlgorithm());
		return new Encapsulation(encapsulated.key(), encapsulated.encapsulation());
	}

	/**
	 * Decapsulates the shared secret from the given ciphertext with the recipient's private key.
	 *
	 * @param recipientPrivateKey
	 *            the recipient's ML-KEM private key
	 * @param ciphertext
	 *            the ciphertext produced by
	 *            {@link #encapsulate(PublicKey, KeyPairGeneratorAlgorithm)}
	 * @param algorithm
	 *            one of {@link KeyPairGeneratorAlgorithm#ML_KEM_512},
	 *            {@link KeyPairGeneratorAlgorithm#ML_KEM_768} or
	 *            {@link KeyPairGeneratorAlgorithm#ML_KEM_1024} - must match the algorithm the
	 *            recipient's key pair was generated with
	 * @return the same shared secret produced by the corresponding
	 *         {@link #encapsulate(PublicKey, KeyPairGeneratorAlgorithm)} call
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no provider supports the given algorithm
	 * @throws InvalidKeyException
	 *             is thrown if the given private key is invalid for the given algorithm
	 * @throws DecapsulateException
	 *             is thrown if the given ciphertext is malformed or does not match the private key
	 */
	public static SecretKey decapsulate(final PrivateKey recipientPrivateKey,
		final byte[] ciphertext, final KeyPairGeneratorAlgorithm algorithm)
		throws NoSuchAlgorithmException, InvalidKeyException, DecapsulateException
	{
		requireMlKem(algorithm);
		return KemFactory.decapsulate(recipientPrivateKey, ciphertext, algorithm.getAlgorithm());
	}

	private static void requireMlKem(final KeyPairGeneratorAlgorithm algorithm)
	{
		Objects.requireNonNull(algorithm);
		if (!algorithm.name().startsWith("ML_KEM_"))
		{
			throw new IllegalArgumentException(
				"algorithm must be one of ML_KEM_512, ML_KEM_768 or ML_KEM_1024 but was "
					+ algorithm);
		}
	}

	/**
	 * The result of an {@link #encapsulate(PublicKey, KeyPairGeneratorAlgorithm)} call: the derived
	 * shared secret and the ciphertext to send to the recipient.
	 */
	public static final class Encapsulation
	{

		private final SecretKey sharedSecret;
		private final byte[] ciphertext;

		/**
		 * Instantiates a new {@link Encapsulation}.
		 *
		 * @param sharedSecret
		 *            the derived shared secret
		 * @param ciphertext
		 *            the ciphertext to send to the recipient
		 */
		public Encapsulation(final SecretKey sharedSecret, final byte[] ciphertext)
		{
			this.sharedSecret = sharedSecret;
			this.ciphertext = ciphertext.clone();
		}

		/**
		 * Gets the derived shared secret.
		 *
		 * @return the derived shared secret
		 */
		public SecretKey getSharedSecret()
		{
			return sharedSecret;
		}

		/**
		 * Gets the ciphertext to send to the recipient.
		 *
		 * @return a defensive copy of the ciphertext
		 */
		public byte[] getCiphertext()
		{
			return ciphertext.clone();
		}

	}

}
