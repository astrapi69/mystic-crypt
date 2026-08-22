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
package io.github.astrapi69.mystic.crypt.aead;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.ArrayUtils;

import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.mystic.crypt.algorithm.MysticSymmetricAlgorithm;
import io.github.astrapi69.mystic.crypt.core.AbstractByteArrayEncryptor;
import io.github.astrapi69.mystic.crypt.sha.Blake2bHasher;
import io.github.astrapi69.random.number.RandomByteFactory;

/**
 * The class {@link KeyCommittingAeadEncryptor} implements key-committing authenticated encryption
 * using AES-GCM with a commitment tag derived from the encryption key.
 * <p>
 * Standard AEAD schemes like AES-GCM are not key-committing: an adversary can potentially find
 * different keys that produce valid decryptions of the same ciphertext. This becomes relevant in
 * multi-recipient scenarios where a ciphertext might be decrypted by multiple parties.
 * </p>
 * <p>
 * This implementation adds a commitment tag computed as Blake2b(key || iv || associatedData) and
 * includes it in the associated data during encryption. During decryption, the commitment is
 * recomputed and verified, ensuring that the ciphertext is bound to the specific key used.
 * </p>
 * <p>
 * Format: IV (12 bytes) || Ciphertext || CommitmentTag (32 bytes)
 * </p>
 *
 * @author Asterios Raptis
 * @since 10.5
 */
public class KeyCommittingAeadEncryptor extends AbstractByteArrayEncryptor
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/** Length of the IV/nonce in bytes (96-bit for GCM). */
	private static final int NONCE_LENGTH = 12;

	/** Length of the GCM authentication tag in bits. */
	private static final int GCM_TAG_LENGTH_BITS = 128;

	/** Length of the commitment tag in bytes (Blake2b output). */
	private static final int COMMITMENT_TAG_LENGTH = 32;

	/** The commitment key derived from the main key. */
	private final SecretKey commitmentKey;

	/**
	 * Instantiates a new {@link KeyCommittingAeadEncryptor} with the given {@link CryptModel}
	 * object.
	 *
	 * @param model
	 *            The crypt model
	 * @throws InvalidAlgorithmParameterException
	 *             if initialization of the cipher object fails
	 * @throws NoSuchPaddingException
	 *             if instantiation of the SecretKeyFactory object fails
	 * @throws InvalidKeySpecException
	 *             if generation of the SecretKey object fails
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails
	 * @throws InvalidKeyException
	 *             if initialization of the cipher object fails
	 * @throws UnsupportedEncodingException
	 *             if the named charset is not supported
	 */
	public KeyCommittingAeadEncryptor(final CryptModel<Cipher, SecretKey, String> model)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(model);
		this.commitmentKey = deriveCommitmentKey(model.getKey());
	}

	/**
	 * Instantiates a new {@link KeyCommittingAeadEncryptor} with the given {@link SecretKey}
	 * object.
	 *
	 * @param symmetricKey
	 *            The symmetric key
	 * @throws InvalidAlgorithmParameterException
	 *             if initialization of the cipher object fails
	 * @throws NoSuchPaddingException
	 *             if instantiation of the SecretKeyFactory object fails
	 * @throws InvalidKeySpecException
	 *             if generation of the SecretKey object fails
	 * @throws NoSuchAlgorithmException
	 *             if instantiation of the SecretKeyFactory object fails
	 * @throws InvalidKeyException
	 *             if initialization of the cipher object fails
	 * @throws UnsupportedEncodingException
	 *             if the named charset is not supported
	 */
	public KeyCommittingAeadEncryptor(final SecretKey symmetricKey)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(symmetricKey);
		this.commitmentKey = deriveCommitmentKey(symmetricKey);
	}

	/**
	 * Derives a commitment key from the main encryption key using Blake2b.
	 *
	 * @param mainKey
	 *            the main encryption key
	 * @return a derived commitment key
	 */
	private SecretKey deriveCommitmentKey(SecretKey mainKey)
	{
		byte[] keyBytes = mainKey.getEncoded();
		byte[] hash = Blake2bHasher.hash(keyBytes, COMMITMENT_TAG_LENGTH);
		return new SecretKeySpec(hash, "AES");
	}

	/**
	 * Computes the commitment tag as Blake2b(commitmentKey || iv || associatedData).
	 *
	 * @param iv
	 *            the initialization vector
	 * @param associatedData
	 *            the associated data (can be null)
	 * @return the commitment tag
	 */
	private byte[] computeCommitmentTag(byte[] iv, byte[] associatedData)
	{
		byte[] keyBytes = commitmentKey.getEncoded();
		byte[] input = ArrayUtils.addAll(keyBytes, iv);
		if (associatedData != null && associatedData.length > 0)
		{
			input = ArrayUtils.addAll(input, associatedData);
		}
		return Blake2bHasher.hash(input, COMMITMENT_TAG_LENGTH);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] encrypt(final byte[] toEncrypt) throws Exception
	{
		return encrypt(toEncrypt, null);
	}

	/**
	 * Encrypts the given data with optional associated data.
	 *
	 * @param toEncrypt
	 *            the data to encrypt
	 * @param associatedData
	 *            the associated data (optional, can be null)
	 * @return the encrypted data with IV prepended and commitment tag appended
	 * @throws Exception
	 *             if encryption fails
	 */
	public byte[] encrypt(final byte[] toEncrypt, final byte[] associatedData) throws Exception
	{
		final String algorithm = MysticSymmetricAlgorithm.AES_GCM_NO_PADDING.getAlgorithm();
		final byte[] iv = RandomByteFactory.randomByteArray(NONCE_LENGTH);

		// Compute commitment tag over key, IV, and associated data
		final byte[] commitmentTag = computeCommitmentTag(iv, associatedData);

		// Include commitment tag in associated data for GCM
		byte[] finalAssociatedData = commitmentTag;
		if (associatedData != null && associatedData.length > 0)
		{
			finalAssociatedData = ArrayUtils.addAll(commitmentTag, associatedData);
		}

		final Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.ENCRYPT_MODE, model.getKey(),
			new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

		if (finalAssociatedData != null)
		{
			cipher.updateAAD(finalAssociatedData);
		}

		byte[] ciphertext = cipher.doFinal(toEncrypt);

		// Format: IV (12) || Ciphertext || CommitmentTag (32)
		byte[] result = Arrays.copyOf(iv, iv.length + ciphertext.length + COMMITMENT_TAG_LENGTH);
		System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
		System.arraycopy(commitmentTag, 0, result, iv.length + ciphertext.length,
			COMMITMENT_TAG_LENGTH);

		return result;
	}

	/**
	 * Decrypts data encrypted with this encryptor.
	 *
	 * @param encrypted
	 *            the encrypted data (IV || Ciphertext || CommitmentTag)
	 * @return the decrypted data
	 * @throws Exception
	 *             if decryption fails or commitment verification fails
	 */
	public byte[] decrypt(final byte[] encrypted) throws Exception
	{
		return decrypt(encrypted, null);
	}

	/**
	 * Decrypts data encrypted with this encryptor, with optional associated data.
	 *
	 * @param encrypted
	 *            the encrypted data (IV || Ciphertext || CommitmentTag)
	 * @param associatedData
	 *            the associated data (optional, can be null)
	 * @return the decrypted data
	 * @throws Exception
	 *             if decryption fails or commitment verification fails
	 */
	public byte[] decrypt(final byte[] encrypted, final byte[] associatedData) throws Exception
	{
		if (encrypted.length < NONCE_LENGTH + COMMITMENT_TAG_LENGTH + 1)
		{
			throw new IllegalArgumentException("Encrypted data too short");
		}

		// Extract IV, ciphertext, and commitment tag
		byte[] iv = Arrays.copyOfRange(encrypted, 0, NONCE_LENGTH);
		byte[] commitmentTag = Arrays.copyOfRange(encrypted,
			encrypted.length - COMMITMENT_TAG_LENGTH, encrypted.length);
		byte[] ciphertext = Arrays.copyOfRange(encrypted, NONCE_LENGTH,
			encrypted.length - COMMITMENT_TAG_LENGTH);

		// Verify commitment tag
		byte[] expectedTag = computeCommitmentTag(iv, associatedData);
		if (!Arrays.equals(commitmentTag, expectedTag))
		{
			throw new SecurityException("Commitment verification failed: key mismatch detected");
		}

		// Reconstruct associated data with commitment tag
		byte[] finalAssociatedData = commitmentTag;
		if (associatedData != null && associatedData.length > 0)
		{
			finalAssociatedData = ArrayUtils.addAll(commitmentTag, associatedData);
		}

		final String algorithm = MysticSymmetricAlgorithm.AES_GCM_NO_PADDING.getAlgorithm();
		final Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(Cipher.DECRYPT_MODE, model.getKey(),
			new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

		if (finalAssociatedData != null)
		{
			cipher.updateAAD(finalAssociatedData);
		}

		return cipher.doFinal(ciphertext);
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * Always returns AES/GCM/NoPadding, regardless of what (if anything) is set on the
	 * {@link CryptModel}: this class hardcodes AES-GCM in {@link #encrypt(byte[], byte[])}/
	 * {@link #decrypt(byte[], byte[])}, so the eagerly-built construction-time cipher (see
	 * {@link io.github.astrapi69.mystic.crypt.core.AbstractCryptor#onInitialize()}) has to agree,
	 * or {@link #newCipher(SecretKey, String, byte[], int, int)} below ends up trying to initialize
	 * a cipher for the default PBE algorithm with a {@link GCMParameterSpec}, which fails with
	 * {@link InvalidKeyException} before this class's own commitment logic ever runs.
	 */
	@Override
	protected String newAlgorithm()
	{
		return MysticSymmetricAlgorithm.AES_GCM_NO_PADDING.getAlgorithm();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Cipher newCipher(final SecretKey key, final String algorithm, final byte[] salt,
		final int iterationCount, final int operationMode)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException
	{
		final byte[] iv = RandomByteFactory.randomByteArray(NONCE_LENGTH);
		return newSymmetricCipher(key, algorithm, iv, operationMode);
	}

	/**
	 * Builds a new {@link Cipher} for AES-GCM.
	 *
	 * @param key
	 *            the key
	 * @param algorithm
	 *            the full cipher transformation
	 * @param iv
	 *            the initialization vector/nonce
	 * @param operationMode
	 *            the operation mode for the new cipher object
	 * @return the initialized cipher
	 */
	private Cipher newSymmetricCipher(final SecretKey key, final String algorithm, final byte[] iv,
		final int operationMode) throws NoSuchAlgorithmException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException
	{
		final Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(operationMode, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
		return cipher;
	}
}
