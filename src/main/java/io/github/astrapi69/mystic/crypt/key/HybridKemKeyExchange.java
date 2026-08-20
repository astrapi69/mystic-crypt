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
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.github.astrapi69.crypt.api.algorithm.AesAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.key.KeyAgreementAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.factory.HkdfExtensions;
import io.github.astrapi69.crypt.data.factory.KemFactory;
import io.github.astrapi69.crypt.data.factory.KeyAgreementFactory;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;

/**
 * The class {@link HybridKemKeyExchange} combines classical X25519 with post-quantum ML-KEM to
 * create a hybrid key encapsulation mechanism that provides security against both classical and
 * quantum adversaries.
 * <p>
 * This hybrid approach follows NIST recommendations for transitioning to post-quantum cryptography:
 * rather than replacing classical algorithms entirely, combine them with PQ algorithms so that
 * the system remains secure even if one of the algorithms is broken.
 * </p>
 * <p>
 * The shared secret is derived by concatenating the X25519 shared secret (32 bytes) and the ML-KEM
 * shared secret (32 bytes for ML-KEM-768), then applying HKDF to produce a uniformly random key
 * of the desired length. This ensures that breaking either algorithm alone does not compromise
 * the shared secret.
 * </p>
 * 
 * @author Asterios Raptis
 * @since 10.2
 */
public final class HybridKemKeyExchange
{

	static
	{
		// Register Bouncy Castle provider if not already registered (needed for ML-KEM)
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private HybridKemKeyExchange()
	{
	}

	/**
	 * Generates a new hybrid key pair consisting of both X25519 and ML-KEM key pairs.
	 *
	 * @param mlKemAlgorithm
	 *            one of {@link KeyPairGeneratorAlgorithm#ML_KEM_512},
	 *            {@link KeyPairGeneratorAlgorithm#ML_KEM_768} or
	 *            {@link KeyPairGeneratorAlgorithm#ML_KEM_1024}
	 * @return the hybrid key pair containing both X25519 and ML-KEM components
	 * @throws NoSuchAlgorithmException
	 *             if X25519 or the specified ML-KEM algorithm is not available
	 * @throws NoSuchProviderException
	 *             if the required provider is not registered
	 */
	public static HybridKeyPair newHybridKeyPair(final KeyPairGeneratorAlgorithm mlKemAlgorithm)
		throws NoSuchAlgorithmException, NoSuchProviderException
	{
		requireMlKem(mlKemAlgorithm);

		// Generate X25519 key pair (JDK native)
		final KeyPair x25519KeyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.X25519);

		// Generate ML-KEM key pair (Bouncy Castle)
		final KeyPair mlKemKeyPair = KeyPairFactory.newKeyPair(mlKemAlgorithm);

		return new HybridKeyPair(x25519KeyPair, mlKemKeyPair, mlKemAlgorithm);
	}

	/**
	 * Encapsulates a hybrid shared secret using both X25519 and ML-KEM.
	 * <p>
	 * The sender needs only the recipient's public keys. This method performs:
	 * </p>
	 * <ol>
	 * <li>X25519 key agreement to produce a 32-byte shared secret</li>
	 * <li>ML-KEM encapsulation to produce another shared secret and ciphertext</li>
	 * <li>HKDF derivation from the concatenated secrets to produce the final key</li>
	 * </ol>
	 *
	 * @param x25519PublicKey
	 *            the recipient's X25519 public key
	 * @param mlKemPublicKey
	 *            the recipient's ML-KEM public key
	 * @param mlKemAlgorithm
	 *            the ML-KEM algorithm (must match the one used to generate the key pair)
	 * @param keyLengthBytes
	 *            the desired length of the derived shared key in bytes (e.g., 32 for AES-256)
	 * @return the hybrid encapsulation result containing the shared secret and ML-KEM ciphertext
	 * @throws InvalidKeyException
	 *             if either public key is invalid
	 * @throws NoSuchAlgorithmException
	 *             if the required algorithms are not available
	 */
	public static HybridEncapsulation hybridEncapsulate(final PublicKey x25519PublicKey,
		final PublicKey mlKemPublicKey, final KeyPairGeneratorAlgorithm mlKemAlgorithm,
		final int keyLengthBytes) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException
	{
		Objects.requireNonNull(x25519PublicKey, "x25519PublicKey cannot be null");
		Objects.requireNonNull(mlKemPublicKey, "mlKemPublicKey cannot be null");
		requireMlKem(mlKemAlgorithm);

		// We need a temporary X25519 key pair for the encapsulation
		final KeyPair tempX25519KeyPair = KeyPairFactory
			.newKeyPair(KeyPairGeneratorAlgorithm.X25519);

		// Step 1: X25519 key agreement
		final byte[] x25519SharedSecret = KeyAgreementFactory.newSharedSecret(
			tempX25519KeyPair.getPrivate(), x25519PublicKey,
			KeyAgreementAlgorithm.X25519.getAlgorithm(), null, true);

		// Step 2: ML-KEM encapsulation
		final var encapsulated = KemFactory.encapsulate(mlKemPublicKey,
			mlKemAlgorithm.getAlgorithm());
		final byte[] mlKemSharedSecret = encapsulated.key().getEncoded();

		try
		{
			// Step 3: Concatenate both secrets
			final byte[] combinedSecret = new byte[x25519SharedSecret.length
				+ mlKemSharedSecret.length];
			System.arraycopy(x25519SharedSecret, 0, combinedSecret, 0,
				x25519SharedSecret.length);
			System.arraycopy(mlKemSharedSecret, 0, combinedSecret,
				x25519SharedSecret.length, mlKemSharedSecret.length);

			// Step 4: Apply HKDF to derive the final key
			final byte[] derivedKey = HkdfExtensions.deriveKey(combinedSecret, null, null,
				keyLengthBytes);

			return new HybridEncapsulation(new SecretKeySpec(derivedKey, AesAlgorithm.AES.getAlgorithm()),
				encapsulated.encapsulation(), tempX25519KeyPair.getPublic());
		}
		finally
		{
			// Secure wipe of intermediate secrets
			Arrays.fill(x25519SharedSecret, (byte) 0);
			Arrays.fill(mlKemSharedSecret, (byte) 0);
		}
	}

	/**
	 * Decapsulates the hybrid shared secret using both X25519 and ML-KEM private keys.
	 * <p>
	 * The recipient uses their private keys to recover the same shared secret that was
	 * created by {@link #hybridEncapsulate(PublicKey, PublicKey, KeyPairGeneratorAlgorithm, int)}.
	 * </p>
	 *
	 * @param x25519PrivateKey
	 *            the recipient's X25519 private key
	 * @param mlKemPrivateKey
	 *            the recipient's ML-KEM private key
	 * @param senderX25519PublicKey
	 *            the sender's X25519 public key (from the encapsulation)
	 * @param mlKemCiphertext
	 *            the ML-KEM ciphertext from the encapsulation
	 * @param mlKemAlgorithm
	 *            the ML-KEM algorithm (must match the one used to generate the key pair)
	 * @param keyLengthBytes
	 *            the desired length of the derived shared key in bytes (e.g., 32 for AES-256)
	 * @return the derived shared {@link SecretKey}
	 * @throws InvalidKeyException
	 *             if any of the keys is invalid
	 * @throws NoSuchAlgorithmException
	 *             if the required algorithms are not available
	 * @throws javax.crypto.DecapsulateException
	 *             if the ML-KEM ciphertext is malformed or does not match the private key
	 */
	public static SecretKey hybridDecapsulate(final PrivateKey x25519PrivateKey,
		final PrivateKey mlKemPrivateKey, final PublicKey senderX25519PublicKey,
		final byte[] mlKemCiphertext, final KeyPairGeneratorAlgorithm mlKemAlgorithm,
		final int keyLengthBytes)
		throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException,
		javax.crypto.DecapsulateException
	{
		Objects.requireNonNull(x25519PrivateKey, "x25519PrivateKey cannot be null");
		Objects.requireNonNull(mlKemPrivateKey, "mlKemPrivateKey cannot be null");
		Objects.requireNonNull(senderX25519PublicKey, "senderX25519PublicKey cannot be null");
		Objects.requireNonNull(mlKemCiphertext, "mlKemCiphertext cannot be null");
		requireMlKem(mlKemAlgorithm);

		// Step 1: X25519 key agreement with sender's public key
		final byte[] x25519SharedSecret = KeyAgreementFactory.newSharedSecret(
			x25519PrivateKey, senderX25519PublicKey,
			KeyAgreementAlgorithm.X25519.getAlgorithm(), null, true);

		// Step 2: ML-KEM decapsulation
		final SecretKey mlKemSharedSecret = KemFactory.decapsulate(mlKemPrivateKey,
			mlKemCiphertext, mlKemAlgorithm.getAlgorithm());
		final byte[] mlKemSecretBytes = mlKemSharedSecret.getEncoded();

		try
		{
			// Step 3: Concatenate both secrets
			final byte[] combinedSecret = new byte[x25519SharedSecret.length
				+ mlKemSecretBytes.length];
			System.arraycopy(x25519SharedSecret, 0, combinedSecret, 0,
				x25519SharedSecret.length);
			System.arraycopy(mlKemSecretBytes, 0, combinedSecret,
				x25519SharedSecret.length, mlKemSecretBytes.length);

			// Step 4: Apply HKDF to derive the final key
			final byte[] derivedKey = HkdfExtensions.deriveKey(combinedSecret, null, null,
				keyLengthBytes);

			return new SecretKeySpec(derivedKey, AesAlgorithm.AES.getAlgorithm());
		}
		finally
		{
			// Secure wipe of intermediate secrets
			Arrays.fill(x25519SharedSecret, (byte) 0);
			Arrays.fill(mlKemSecretBytes, (byte) 0);
		}
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
	 * Represents a hybrid key pair containing both X25519 and ML-KEM components.
	 */
	public static final class HybridKeyPair
	{
		private final KeyPair x25519KeyPair;
		private final KeyPair mlKemKeyPair;
		private final KeyPairGeneratorAlgorithm mlKemAlgorithm;

		/**
		 * Instantiates a new {@link HybridKeyPair}.
		 *
		 * @param x25519KeyPair
		 *            the X25519 key pair
		 * @param mlKemKeyPair
		 *            the ML-KEM key pair
		 * @param mlKemAlgorithm
		 *            the ML-KEM algorithm used
		 */
		public HybridKeyPair(final KeyPair x25519KeyPair, final KeyPair mlKemKeyPair,
			final KeyPairGeneratorAlgorithm mlKemAlgorithm)
		{
			this.x25519KeyPair = Objects.requireNonNull(x25519KeyPair);
			this.mlKemKeyPair = Objects.requireNonNull(mlKemKeyPair);
			this.mlKemAlgorithm = Objects.requireNonNull(mlKemAlgorithm);
		}

		/**
		 * Gets the X25519 key pair.
		 *
		 * @return the X25519 key pair
		 */
		public KeyPair getX25519KeyPair()
		{
			return x25519KeyPair;
		}

		/**
		 * Gets the ML-KEM key pair.
		 *
		 * @return the ML-KEM key pair
		 */
		public KeyPair getMlKemKeyPair()
		{
			return mlKemKeyPair;
		}

		/**
		 * Gets the ML-KEM algorithm.
		 *
		 * @return the ML-KEM algorithm
		 */
		public KeyPairGeneratorAlgorithm getMlKemAlgorithm()
		{
			return mlKemAlgorithm;
		}

		/**
		 * Gets the combined public key structure containing both X25519 and ML-KEM public keys.
		 *
		 * @return the hybrid public key
		 */
		public HybridPublicKey getHybridPublicKey()
		{
			return new HybridPublicKey(x25519KeyPair.getPublic(), mlKemKeyPair.getPublic(),
				mlKemAlgorithm);
		}

		/**
		 * Gets the combined private key structure containing both X25519 and ML-KEM private keys.
		 *
		 * @return the hybrid private key
		 */
		public HybridPrivateKey getHybridPrivateKey()
		{
			return new HybridPrivateKey(x25519KeyPair.getPrivate(), mlKemKeyPair.getPrivate());
		}
	}

	/**
	 * Represents a hybrid public key containing both X25519 and ML-KEM public keys.
	 */
	public static final class HybridPublicKey
	{
		private final PublicKey x25519PublicKey;
		private final PublicKey mlKemPublicKey;
		private final KeyPairGeneratorAlgorithm mlKemAlgorithm;

		/**
		 * Instantiates a new {@link HybridPublicKey}.
		 *
		 * @param x25519PublicKey
		 *            the X25519 public key
		 * @param mlKemPublicKey
		 *            the ML-KEM public key
		 * @param mlKemAlgorithm
		 *            the ML-KEM algorithm
		 */
		public HybridPublicKey(final PublicKey x25519PublicKey,
			final PublicKey mlKemPublicKey, final KeyPairGeneratorAlgorithm mlKemAlgorithm)
		{
			this.x25519PublicKey = Objects.requireNonNull(x25519PublicKey);
			this.mlKemPublicKey = Objects.requireNonNull(mlKemPublicKey);
			this.mlKemAlgorithm = Objects.requireNonNull(mlKemAlgorithm);
		}

		/**
		 * Gets the X25519 public key.
		 *
		 * @return the X25519 public key
		 */
		public PublicKey getX25519PublicKey()
		{
			return x25519PublicKey;
		}

		/**
		 * Gets the ML-KEM public key.
		 *
		 * @return the ML-KEM public key
		 */
		public PublicKey getMlKemPublicKey()
		{
			return mlKemPublicKey;
		}

		/**
		 * Gets the ML-KEM algorithm.
		 *
		 * @return the ML-KEM algorithm
		 */
		public KeyPairGeneratorAlgorithm getMlKemAlgorithm()
		{
			return mlKemAlgorithm;
		}
	}

	/**
	 * Represents a hybrid private key containing both X25519 and ML-KEM private keys.
	 */
	public static final class HybridPrivateKey
	{
		private final PrivateKey x25519PrivateKey;
		private final PrivateKey mlKemPrivateKey;

		/**
		 * Instantiates a new {@link HybridPrivateKey}.
		 *
		 * @param x25519PrivateKey
		 *            the X25519 private key
		 * @param mlKemPrivateKey
		 *            the ML-KEM private key
		 */
		public HybridPrivateKey(final PrivateKey x25519PrivateKey,
			final PrivateKey mlKemPrivateKey)
		{
			this.x25519PrivateKey = Objects.requireNonNull(x25519PrivateKey);
			this.mlKemPrivateKey = Objects.requireNonNull(mlKemPrivateKey);
		}

		/**
		 * Gets the X25519 private key.
		 *
		 * @return the X25519 private key
		 */
		public PrivateKey getX25519PrivateKey()
		{
			return x25519PrivateKey;
		}

		/**
		 * Gets the ML-KEM private key.
		 *
		 * @return the ML-KEM private key
		 */
		public PrivateKey getMlKemPrivateKey()
		{
			return mlKemPrivateKey;
		}
	}

	/**
	 * The result of a {@link #hybridEncapsulate(PublicKey, PublicKey, KeyPairGeneratorAlgorithm, int)}
	 * call: the derived shared secret, the ML-KEM ciphertext, and the sender's X25519 public key.
	 */
	public static final class HybridEncapsulation
	{
		private final SecretKey sharedSecret;
		private final byte[] mlKemCiphertext;
		private final PublicKey senderX25519PublicKey;

		/**
		 * Instantiates a new {@link HybridEncapsulation}.
		 *
		 * @param sharedSecret
		 *            the derived shared secret
		 * @param mlKemCiphertext
		 *            the ML-KEM ciphertext
		 * @param senderX25519PublicKey
		 *            the sender's X25519 public key
		 */
		public HybridEncapsulation(final SecretKey sharedSecret, final byte[] mlKemCiphertext,
			final PublicKey senderX25519PublicKey)
		{
			this.sharedSecret = Objects.requireNonNull(sharedSecret);
			this.mlKemCiphertext = Objects.requireNonNull(mlKemCiphertext).clone();
			this.senderX25519PublicKey = Objects.requireNonNull(senderX25519PublicKey);
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
		 * Gets the ML-KEM ciphertext.
		 *
		 * @return a defensive copy of the ML-KEM ciphertext
		 */
		public byte[] getMlKemCiphertext()
		{
			return mlKemCiphertext.clone();
		}

		/**
		 * Gets the sender's X25519 public key needed for decapsulation.
		 *
		 * @return the sender's X25519 public key
		 */
		public PublicKey getSenderX25519PublicKey()
		{
			return senderX25519PublicKey;
		}
	}

}
