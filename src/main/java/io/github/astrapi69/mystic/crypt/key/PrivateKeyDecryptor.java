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

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.SerializationUtils;

import io.github.astrapi69.crypt.api.ByteArrayDecryptor;
import io.github.astrapi69.crypt.api.algorithm.AesAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.Algorithm;
import io.github.astrapi69.crypt.api.algorithm.key.KeyPairWithModeAndPaddingAlgorithm;
import io.github.astrapi69.crypt.data.factory.CipherFactory;
import io.github.astrapi69.crypt.data.model.AesRsaCryptModel;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.mystic.crypt.algorithm.MysticSymmetricAlgorithm;
import io.github.astrapi69.mystic.crypt.core.AbstractDecryptor;

/**
 * The class {@link PrivateKeyDecryptor} decrypts encrypted byte array the was encrypted with the
 * public key of the pendant private key of this class.
 */
public class PrivateKeyDecryptor extends AbstractDecryptor<Cipher, PrivateKey, byte[]>
	implements
		ByteArrayDecryptor
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/** The symmetric transformation used to decrypt the payload. */
	private final Algorithm symmetricAlgorithm;

	/**
	 * Instantiates a new {@link PrivateKeyDecryptor} with the given {@link CryptModel}.
	 *
	 * @param model
	 *            The crypt model.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public PrivateKeyDecryptor(final CryptModel<Cipher, PrivateKey, byte[]> model)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		this(model, MysticSymmetricAlgorithm.AES_GCM_NO_PADDING);
	}

	/**
	 * Instantiates a new {@link PrivateKeyDecryptor} with the given {@link CryptModel} and an
	 * explicit symmetric transformation. Use this to decrypt data whose symmetric leg was encrypted
	 * with an explicitly configured, non-default transformation on {@code PublicKeyEncryptor}'s
	 * {@code symmetricKeyModel} (e.g. the legacy {@link AesAlgorithm#AES}).
	 *
	 * @param model
	 *            The crypt model.
	 * @param symmetricAlgorithm
	 *            the symmetric transformation that was used to encrypt the payload
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public PrivateKeyDecryptor(final CryptModel<Cipher, PrivateKey, byte[]> model,
		final Algorithm symmetricAlgorithm)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(model);
		Objects.requireNonNull(symmetricAlgorithm);
		this.symmetricAlgorithm = symmetricAlgorithm;
	}

	/**
	 * Instantiates a new {@link PrivateKeyDecryptor} with the given {@link PrivateKey}
	 *
	 * @param privateKey
	 *            The private key
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public PrivateKeyDecryptor(final PrivateKey privateKey)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		this(CryptModel.<Cipher, PrivateKey, byte[]> builder().key(privateKey).build());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] decrypt(final byte[] encrypted) throws Exception
	{
		AesRsaCryptModel cryptData = SerializationUtils.deserialize(encrypted);
		byte[] decryptedKey = getModel().getCipher().doFinal(cryptData.getEncryptedKey());
		byte[] symmetricBlob = cryptData.getSymmetricKeyEncryptedObject();
		String algorithm = symmetricAlgorithm.getAlgorithm();
		if (isGcmTransformation(algorithm))
		{
			if (symmetricBlob.length < GCM_IV_LENGTH)
			{
				throw new IllegalArgumentException(
					"encrypted data too short to contain a GCM initialization vector");
			}
			byte[] iv = ArrayUtils.subarray(symmetricBlob, 0, GCM_IV_LENGTH);
			byte[] cipherBytes = ArrayUtils.subarray(symmetricBlob, GCM_IV_LENGTH,
				symmetricBlob.length);
			Cipher cipher = newSymmetricCipher(decryptedKey, algorithm, iv, Cipher.DECRYPT_MODE);
			return cipher.doFinal(cipherBytes);
		}
		Cipher cipher = newSymmetricCipher(decryptedKey, algorithm, null, Cipher.DECRYPT_MODE);
		return cipher.doFinal(symmetricBlob);
	}

	private Cipher newSymmetricCipher(byte[] decryptedKey, final String algorithm, final byte[] iv,
		final int operationMode) throws NoSuchPaddingException, NoSuchAlgorithmException,
		InvalidKeyException, InvalidAlgorithmParameterException
	{
		SecretKey originalKey = new SecretKeySpec(decryptedKey, 0, decryptedKey.length,
			AesAlgorithm.AES.getAlgorithm());
		final Cipher cipher = Cipher.getInstance(algorithm);
		if (isGcmTransformation(algorithm))
		{
			cipher.init(operationMode, originalKey, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
		}
		else
		{
			cipher.init(operationMode, originalKey);
		}
		return cipher;
	}

	/**
	 * Checks if the given transformation is the GCM transformation used as the new default.
	 *
	 * @param algorithm
	 *            the transformation to check
	 * @return true if it is the GCM transformation
	 */
	private static boolean isGcmTransformation(final String algorithm)
	{
		return MysticSymmetricAlgorithm.AES_GCM_NO_PADDING.getAlgorithm().equals(algorithm);
	}

	/** The length in bytes of a GCM initialization vector (96-bit nonce, NIST SP 800-38D). */
	private static final int GCM_IV_LENGTH = 12;

	/** The length in bits of the GCM authentication tag. */
	private static final int GCM_TAG_LENGTH_BITS = 128;

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected String newAlgorithm()
	{
		if (getModel().getAlgorithm() == null)
		{
			getModel().setAlgorithm(
				KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA1AndMGF1Padding);
		}
		return getModel().getAlgorithm().getAlgorithm();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected Cipher newCipher(final PrivateKey key, final String algorithm, final byte[] salt,
		final int iterationCount, final int operationMode)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		final Cipher cipher = CipherFactory.newCipher(algorithm);
		cipher.init(operationMode, key);
		return cipher;
	}

}
