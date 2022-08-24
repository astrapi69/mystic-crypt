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
package io.github.astrapi69.crypto.key;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.commons.lang3.SerializationUtils;

import io.github.astrapi69.crypto.algorithm.AesAlgorithm;
import io.github.astrapi69.crypto.algorithm.KeyPairWithModeAndPaddingAlgorithm;
import io.github.astrapi69.crypto.api.ByteArrayEncryptor;
import io.github.astrapi69.crypto.core.AbstractEncryptor;
import io.github.astrapi69.crypt.data.factory.CipherFactory;
import io.github.astrapi69.crypt.data.factory.SecretKeyFactoryExtensions;
import io.github.astrapi69.crypt.data.model.AesRsaCryptModel;
import io.github.astrapi69.crypt.data.model.CryptModel;

/**
 * The class {@link PublicKeyEncryptor} can encrypt a byte array with his public key.
 */
public class PublicKeyEncryptor extends AbstractEncryptor<Cipher, PublicKey, byte[]>
	implements
		ByteArrayEncryptor
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;
	private CryptModel<Cipher, SecretKey, String> symmetricKeyModel;

	/**
	 * Instantiates a new {@link PublicKeyEncryptor} with the given {@link CryptModel} for the
	 * public key and the given {@link CryptModel} for the symmetric key
	 *
	 * @param model
	 *            The crypt model
	 * @param symmetricKeyModel
	 *            The symmetric key model
	 *
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
	public PublicKeyEncryptor(final CryptModel<Cipher, PublicKey, byte[]> model,
		final CryptModel<Cipher, SecretKey, String> symmetricKeyModel)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(model);
		Objects.requireNonNull(symmetricKeyModel);
		this.symmetricKeyModel = symmetricKeyModel;
	}

	/**
	 * Instantiates a new {@link PublicKeyEncryptor} object with the given {@link PublicKey}
	 *
	 * @param publicKey
	 *            the public key
	 *
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public PublicKeyEncryptor(final PublicKey publicKey)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		super(CryptModel.<Cipher, PublicKey, byte[]> builder().key(publicKey).build());
		this.symmetricKeyModel = CryptModel.<Cipher, SecretKey, String> builder()
			.key(SecretKeyFactoryExtensions.newSecretKey(AesAlgorithm.AES.getAlgorithm(), 128))
			.algorithm(AesAlgorithm.AES).operationMode(Cipher.ENCRYPT_MODE).build();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] encrypt(final byte[] toEncrypt) throws Exception
	{
		final SecretKey symmetricKey = symmetricKeyModel.getKey();
		Cipher symmetricKeyCipher = newSymmetricCipher(symmetricKey,
			symmetricKeyModel.getAlgorithm().getAlgorithm(), symmetricKeyModel.getOperationMode());
		byte[] symmetricKeyEncryptedBytes = symmetricKeyCipher.doFinal(toEncrypt);
		byte[] encryptedKey = getModel().getCipher().doFinal(symmetricKey.getEncoded());
		AesRsaCryptModel cryptData = AesRsaCryptModel.builder().encryptedKey(encryptedKey)
			.symmetricKeyEncryptedObject(symmetricKeyEncryptedBytes).build();
		byte[] encryptedCryptData = SerializationUtils.serialize(cryptData);
		return encryptedCryptData;
	}

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
	protected Cipher newCipher(final PublicKey key, final String algorithm, final byte[] salt,
		final int iterationCount, final int operationMode)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		final Cipher cipher = CipherFactory.newCipher(algorithm);
		cipher.init(Cipher.PUBLIC_KEY, key);
		return cipher;
	}

	private Cipher newSymmetricCipher(final SecretKey key, final String algorithm,
		final int operationMode)
		throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException
	{
		final Cipher cipher = Cipher.getInstance(algorithm);
		cipher.init(operationMode, key);
		return cipher;
	}

}
