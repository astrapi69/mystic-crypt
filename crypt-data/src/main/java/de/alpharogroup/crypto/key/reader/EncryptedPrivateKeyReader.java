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
package de.alpharogroup.crypto.key.reader;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;

import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.factories.CipherFactory;
import de.alpharogroup.crypto.factories.KeySpecFactory;
import de.alpharogroup.crypto.factories.SecretKeyFactoryExtensions;
import de.alpharogroup.crypto.provider.SecurityProvider;
import lombok.experimental.UtilityClass;

/**
 * The class {@link EncryptedPrivateKeyReader} is a utility class for reading encrypted private keys
 * that are protected with a password.
 */
@UtilityClass
public final class EncryptedPrivateKeyReader
{

	/**
	 * Reads the given byte array that contains a password protected private key.
	 *
	 * @param encryptedPrivateKeyBytes
	 *            the byte array that contains the password protected private key
	 * @param password
	 *            the password
	 * @param algorithm
	 *            the algorithm
	 * @return the {@link PrivateKey} object
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws NoSuchPaddingException
	 *             the no such padding exception
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 */
	public static PrivateKey readPasswordProtectedPrivateKey(final byte[] encryptedPrivateKeyBytes,
		final String password, final String algorithm)
		throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
		InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		final EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(
			encryptedPrivateKeyBytes);
		final String algName = encryptedPrivateKeyInfo.getAlgName();
		final Cipher cipher = CipherFactory.newCipher(algName);
		final KeySpec pbeKeySpec = KeySpecFactory.newPBEKeySpec(password);
		final SecretKeyFactory secretKeyFactory = SecretKeyFactoryExtensions
			.newSecretKeyFactory(algName);
		final Key pbeKey = secretKeyFactory.generateSecret(pbeKeySpec);
		final AlgorithmParameters algParameters = encryptedPrivateKeyInfo.getAlgParameters();
		cipher.init(Cipher.DECRYPT_MODE, pbeKey, algParameters);
		final KeySpec pkcs8KeySpec = encryptedPrivateKeyInfo.getKeySpec(cipher);
		final KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		return keyFactory.generatePrivate(pkcs8KeySpec);
	}

	/**
	 * Reads from the given {@link File} that contains the password protected private key and
	 * returns it
	 *
	 * @param encryptedPrivateKeyFile
	 *            the file that contains the password protected private key
	 * @param password
	 *            the password
	 * @param algorithm
	 *            the algorithm
	 * @return the {@link PrivateKey} object
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws NoSuchPaddingException
	 *             the no such padding exception
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 */
	public static PrivateKey readPasswordProtectedPrivateKey(final File encryptedPrivateKeyFile,
		final String password, final String algorithm)
		throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
		InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		byte[] encryptedPrivateKeyBytes = null;
		boolean pemFormat = PrivateKeyReader.isPemFormat(encryptedPrivateKeyFile);
		if (pemFormat)
		{
			KeyPair keyPair = getKeyPair(encryptedPrivateKeyFile, password);
			if (keyPair != null)
			{
				return keyPair.getPrivate();
			}
		}
		else
		{
			encryptedPrivateKeyBytes = Files.readAllBytes(encryptedPrivateKeyFile.toPath());
			return readPasswordProtectedPrivateKey(encryptedPrivateKeyBytes, password, algorithm);
		}
		return null;
	}

	/**
	 * Reads from the given {@link File} that contains the password protected {@link KeyPair} and
	 * returns it
	 *
	 * @param encryptedPrivateKeyFile
	 *            the file that contains the password protected {@link KeyPair}
	 * @param password
	 *            the password
	 * @return the key pair
	 * @throws FileNotFoundException
	 *             is thrown if the file did not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws PEMException
	 *             is thrown if an error occurs on read the pem file
	 */
	public static KeyPair getKeyPair(final File encryptedPrivateKeyFile, final String password)
		throws FileNotFoundException, IOException, PEMException
	{
		PEMParser pemParser = new PEMParser(new FileReader(encryptedPrivateKeyFile));
		Object pemObject = pemParser.readObject();
		pemParser.close();

		JcaPEMKeyConverter keyConverter = new JcaPEMKeyConverter()
			.setProvider(SecurityProvider.BC.name());
		KeyPair keyPair;
		if (pemObject instanceof PEMEncryptedKeyPair)
		{
			PEMDecryptorProvider decryptorProvider = new JcePEMDecryptorProviderBuilder()
				.setProvider(SecurityProvider.BC.name()).build(password.toCharArray());
			keyPair = keyConverter
				.getKeyPair(((PEMEncryptedKeyPair)pemObject).decryptKeyPair(decryptorProvider));
		}
		else
		{
			keyPair = keyConverter.getKeyPair((PEMKeyPair)pemObject);
		}
		return keyPair;
	}

	/**
	 * Reads the given {@link File} that contains a password protected private key.
	 *
	 * @param encryptedPrivateKeyFile
	 *            the file that contains the password protected private key
	 * @param password
	 *            the password
	 * @return the {@link PrivateKey} object
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws NoSuchPaddingException
	 *             the no such padding exception
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 */
	public static PrivateKey readPasswordProtectedPrivateKey(final File encryptedPrivateKeyFile,
		final String password) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
		InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		return readPasswordProtectedPrivateKey(encryptedPrivateKeyFile, password,
			KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
	}

}
