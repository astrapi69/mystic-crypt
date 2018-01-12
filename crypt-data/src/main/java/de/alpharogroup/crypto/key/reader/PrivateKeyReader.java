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
import java.io.IOException;
import java.nio.file.Files;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;

import org.apache.commons.codec.binary.Base64;

import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.factories.CipherFactory;
import de.alpharogroup.crypto.factories.KeySpecFactory;
import de.alpharogroup.crypto.factories.SecretKeyFactoryExtensions;
import lombok.experimental.UtilityClass;

/**
 * The class {@link PrivateKeyReader} is a utility class for reading private keys.
 */
@UtilityClass
public class PrivateKeyReader
{

	/** The Constant RSA_PRIVATE_KEY. */
	public static final String RSA_PRIVATE_KEY = "RSA PRIVATE KEY";

	/** The Constant BEGIN_PRIVATE_KEY_PREFIX. */
	public static final String BEGIN_PRIVATE_KEY_PREFIX = "-----BEGIN PRIVATE KEY-----";

	/** The Constant END_PRIVATE_KEY_SUFFIX. */
	public static final String END_PRIVATE_KEY_SUFFIX = "-----END PRIVATE KEY-----";

	/** The Constant BEGIN_RSA_PRIVATE_KEY_PREFIX. */
	public static final String BEGIN_RSA_PRIVATE_KEY_PREFIX = "-----BEGIN " + RSA_PRIVATE_KEY
		+ "-----\n";

	/** The Constant END_RSA_PRIVATE_KEY_SUFFIX. */
	public static final String END_RSA_PRIVATE_KEY_SUFFIX = "\n-----END " + RSA_PRIVATE_KEY
		+ "-----";

	/**
	 * Read private key.
	 *
	 * @param file
	 *            the file
	 * @return the private key
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	public static PrivateKey readPrivateKey(final File file) throws IOException,
		NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		return readPrivateKey(file, KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
	}

	/**
	 * Read private key.
	 *
	 * @param file
	 *            the file
	 * @param algorithm
	 *            the algorithm
	 * @return the private key
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	public static PrivateKey readPrivateKey(final File file, final String algorithm)
		throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException
	{
		final byte[] keyBytes = Files.readAllBytes(file.toPath());
		return readPrivateKey(keyBytes, algorithm);
	}

	/**
	 * Read private key.
	 *
	 * @param privateKeyBytes
	 *            the private key bytes
	 * @param provider
	 *            the provider
	 * @return the private key
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	public static PrivateKey readPrivateKey(final byte[] privateKeyBytes)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		return readPrivateKey(privateKeyBytes, KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
	}

	/**
	 * Read private key.
	 *
	 * @param privateKeyBytes
	 *            the private key bytes
	 * @param provider
	 *            the provider
	 * @param algorithm
	 *            the algorithm for the {@link KeyFactory}
	 * @return the private key
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	public static PrivateKey readPrivateKey(final byte[] privateKeyBytes, final String algorithm)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		final KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		final PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		return privateKey;
	}

	/**
	 * Read private key.
	 *
	 * @param encryptedPrivateKeyBytes
	 *            the encrypted private key bytes
	 * @param algorithm
	 *            the algorithm for the {@link KeyFactory}
	 * @param password
	 *            the password
	 * @return the private key
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 * @throws InvalidKeyException
	 *             the invalid key exception
	 * @throws NoSuchPaddingException
	 *             the no such padding exception
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static PrivateKey readEncryptedPrivateKey(final byte[] encryptedPrivateKeyBytes,
		final String algorithm, final String password)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException,
		InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException
	{
		return decryptPasswordProtectedPrivateKey(encryptedPrivateKeyBytes, password, algorithm);
	}

	/**
	 * Read pem private key.
	 *
	 * @param file
	 *            the file
	 * @param securityProvider
	 *            the security provider
	 * @return the private key
	 * @throws Exception
	 *             is thrown if if a security error occur
	 */
	public static PrivateKey readPemPrivateKey(final File file) throws Exception
	{
		final String privateKeyAsString = readPemFileAsBase64(file);
		final byte[] decoded = new Base64().decode(privateKeyAsString);
		return readPrivateKey(decoded);
	}


	/**
	 * Read the private key from a pem file as base64 encoded {@link String} value.
	 *
	 * @param file
	 *            the file in pem format that contains the private key.
	 * @return the base64 encoded {@link String} value.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static String readPemFileAsBase64(final File file) throws IOException
	{
		final byte[] keyBytes = Files.readAllBytes(file.toPath());
		final String privateKeyPem = new String(keyBytes);
		String privateKeyAsBase64String = null;
		if (privateKeyPem.indexOf(BEGIN_PRIVATE_KEY_PREFIX) != -1)
		{
			// PKCS#8 format
			privateKeyAsBase64String = new String(keyBytes).replace(BEGIN_PRIVATE_KEY_PREFIX, "")
				.replace(END_PRIVATE_KEY_SUFFIX, "").trim();
		}
		if (privateKeyPem.indexOf(BEGIN_RSA_PRIVATE_KEY_PREFIX) != -1)
		{
			// PKCS#1 format
			privateKeyAsBase64String = new String(keyBytes)
				.replace(BEGIN_RSA_PRIVATE_KEY_PREFIX, "").replace(END_RSA_PRIVATE_KEY_SUFFIX, "")
				.trim();
		}
		return privateKeyAsBase64String;
	}

	/**
	 * Decrypts the given byte array that represents a password protected private key.
	 *
	 * @param encryptedPrivateKeyBytes
	 *            the byte array that represents a password protected private key
	 * @param algorithm
	 *            the algorithm
	 * @param password
	 *            the password
	 * @return the private key
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws NoSuchPaddingException
	 *             the no such padding exception
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws InvalidKeyException
	 *             the invalid key exception
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 */
	public static PrivateKey decryptPasswordProtectedPrivateKey(
		final byte[] encryptedPrivateKeyBytes, final String algorithm, final String password)
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

}
