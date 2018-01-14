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
package de.alpharogroup.crypto.key.writer;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.factories.AlgorithmParameterSpecFactory;
import de.alpharogroup.crypto.factories.SecretKeyFactoryExtensions;
import lombok.NonNull;
import lombok.experimental.UtilityClass;

/**
 * The class {@link EncryptedPrivateKeyWriter} is a utility class for write and protect
 * {@link PrivateKey} objects with a password to files.
 *
 * @author Asterios Raptis
 */
@UtilityClass
public final class EncryptedPrivateKeyWriter
{

	/**
	 * Encrypt the given {@link PrivateKey} with the given password and return the resulted byte
	 * array.
	 *
	 * @param privateKey
	 *            the private key to encrypt
	 * @param password
	 *            the password
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             the no such padding exception
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws IllegalBlockSizeException
	 *             the illegal block size exception
	 * @throws BadPaddingException
	 *             the bad padding exception
	 * @throws InvalidParameterSpecException
	 *             the invalid parameter spec exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static byte[] encryptPrivateKeyWithPassword(final PrivateKey privateKey,
		final String password) throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
		IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, IOException
	{
		final byte[] privateKeyEncoded = privateKey.getEncoded();

		final SecureRandom random = new SecureRandom();
		final byte[] salt = new byte[8];
		random.nextBytes(salt);

		final AlgorithmParameterSpec algorithmParameterSpec = AlgorithmParameterSpecFactory
			.newPBEParameterSpec(salt, 20);

		final SecretKey secretKey = SecretKeyFactoryExtensions.newSecretKey(password.toCharArray(),
			CryptConst.PBE_WITH_SHA1_AND_DES_EDE);

		final Cipher pbeCipher = Cipher.getInstance(CryptConst.PBE_WITH_SHA1_AND_DES_EDE);

		pbeCipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec);

		final byte[] ciphertext = pbeCipher.doFinal(privateKeyEncoded);

		final AlgorithmParameters algparms = AlgorithmParameters
			.getInstance(CryptConst.PBE_WITH_SHA1_AND_DES_EDE);
		algparms.init(algorithmParameterSpec);
		final EncryptedPrivateKeyInfo encinfo = new EncryptedPrivateKeyInfo(algparms, ciphertext);

		return encinfo.getEncoded();
	}

	/**
	 * Encrypt the given {@link PrivateKey} with the given password and write the result to the
	 * given {@link OutputStream}.
	 *
	 * @param privateKey
	 *            the private key to encrypt
	 * @param outputStream
	 *            the output stream
	 * @param password
	 *            the password
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             the no such padding exception
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws IllegalBlockSizeException
	 *             the illegal block size exception
	 * @throws BadPaddingException
	 *             the bad padding exception
	 * @throws InvalidParameterSpecException
	 *             the invalid parameter spec exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void encryptPrivateKeyWithPassword(final PrivateKey privateKey,
		final @NonNull OutputStream outputStream, final String password)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
		BadPaddingException, InvalidParameterSpecException, IOException
	{
		final byte[] encryptedPrivateKeyWithPasswordBytes = encryptPrivateKeyWithPassword(
			privateKey, password);
		outputStream.write(encryptedPrivateKeyWithPasswordBytes);
		outputStream.close();
	}

	/**
	 * Encrypt the given {@link PrivateKey} with the given password and write the result to the
	 * given {@link File}.
	 *
	 * @param privateKey
	 *            the private key to encrypt
	 * @param file
	 *            the file
	 * @param password
	 *            the password
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             the no such padding exception
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws IllegalBlockSizeException
	 *             the illegal block size exception
	 * @throws BadPaddingException
	 *             the bad padding exception
	 * @throws InvalidParameterSpecException
	 *             the invalid parameter spec exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void encryptPrivateKeyWithPassword(final PrivateKey privateKey, final File file,
		final String password) throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
		IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, IOException
	{
		encryptPrivateKeyWithPassword(privateKey, new FileOutputStream(file), password);
	}

}
