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
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;

import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.provider.SecurityProvider;
import lombok.experimental.UtilityClass;

/**
 * The class {@link PrivateKeyReader} is a utility class for reading private keys.
 */
@UtilityClass
public class PrivateKeyReader
{

	/** The Constant END_PRIVATE_KEY_SUFFIX. */
	public static final String END_PRIVATE_KEY_SUFFIX = "-----END PRIVATE KEY-----";

	/** The Constant BEGIN_PRIVATE_KEY_PREFIX. */
	public static final String BEGIN_PRIVATE_KEY_PREFIX = "-----BEGIN PRIVATE KEY-----";

	/** The Constant END_RSA_PRIVATE_KEY_SUFFIX. */
	public static final String END_RSA_PRIVATE_KEY_SUFFIX = "\n-----END RSA PRIVATE KEY-----";

	/** The Constant BEGIN_RSA_PRIVATE_KEY_PREFIX. */
	public static final String BEGIN_RSA_PRIVATE_KEY_PREFIX = "-----BEGIN RSA PRIVATE KEY-----\n";

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
		return readPrivateKey(file, "BC");
	}

	/**
	 * Read private key.
	 *
	 * @param file
	 *            the file
	 * @param provider
	 *            the security provider
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
	public static PrivateKey readPrivateKey(final File file, final String provider)
		throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException
	{
		final byte[] keyBytes = Files.readAllBytes(file.toPath());
		return readPrivateKey(keyBytes, provider);
	}

	/**
	 * Read private key.
	 *
	 * @param file
	 *            the file
	 * @param securityProvider
	 *            the security provider
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
	public static PrivateKey readPrivateKey(final File file,
		final SecurityProvider securityProvider) throws IOException, NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException
	{
		return readPrivateKey(file, securityProvider.name());
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
	public static PrivateKey readPrivateKey(final byte[] privateKeyBytes, final String provider)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		return readPrivateKey(privateKeyBytes, provider,
			KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
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
	public static PrivateKey readPrivateKey(final byte[] privateKeyBytes, final String provider,
		final String algorithm)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		final KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		final PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		return privateKey;
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
	public static PrivateKey readPemPrivateKey(final File file,
		final SecurityProvider securityProvider) throws Exception
	{
		final String privateKeyAsString = readPemFileAsBase64(file);
		final byte[] decoded = new Base64().decode(privateKeyAsString);
		return readPrivateKey(decoded, securityProvider);
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
		final String privateKeyAsBase64String = new String(keyBytes)
			.replace(BEGIN_RSA_PRIVATE_KEY_PREFIX, "")
			.replace(END_RSA_PRIVATE_KEY_SUFFIX, "")
			.trim();
		return privateKeyAsBase64String;
	}

	/**
	 * Read private key.
	 *
	 * @param privateKeyBytes
	 *            the private key bytes
	 * @param securityProvider
	 *            the security provider
	 * @return the private key
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	public static PrivateKey readPrivateKey(final byte[] privateKeyBytes,
		final SecurityProvider securityProvider)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		return readPrivateKey(privateKeyBytes, securityProvider.name());
	}

}
