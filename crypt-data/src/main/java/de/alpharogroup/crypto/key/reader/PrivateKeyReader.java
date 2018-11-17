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
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;

/**
 * The class {@link PrivateKeyReader} is a utility class for reading private keys in *.der or *.pem
 * format.
 */
@UtilityClass
@Slf4j
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
	 * Checks if the given {@link File}( in *.der format) is password protected
	 *
	 * @param file
	 *            the file( in *.der format) that contains the private key
	 * @return true, if if the given {@link File}( in *.der format) is password protected otherwise
	 *         false
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static boolean isPrivateKeyPasswordProtected(final File file) throws IOException
	{
		boolean result = false;
		if (isPemFormat(file))
		{
			try
			{
				readPemPrivateKey(file);
			}
			catch (Exception e)
			{
				log.error(e.getMessage(), e);
				result = true;
			}
		}
		else
		{
			try
			{
				readPrivateKey(file);
			}
			catch (Exception e)
			{
				log.error(e.getMessage(), e);
				result = true;
			}
		}


		return result;
	}

	/**
	 * Checks if the given {@link File} is in pem format.
	 *
	 * @param file
	 *            the file
	 * @return true, if the given {@link File} is in pem format otherwise false
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static boolean isPemFormat(final File file) throws IOException
	{
		boolean result = false;
		final byte[] keyBytes = Files.readAllBytes(file.toPath());
		final String privateKeyPem = new String(keyBytes);
		if (privateKeyPem.indexOf(BEGIN_PRIVATE_KEY_PREFIX) != -1)
		{
			result = true;
			return result;
		}
		if (privateKeyPem.indexOf(BEGIN_RSA_PRIVATE_KEY_PREFIX) != -1)
		{
			result = true;
			return result;
		}
		return result;
	}

	/**
	 * Reads the given {@link File}( in *.der format) with the default RSA algorithm and returns the
	 * {@link PrivateKey} object.
	 *
	 * @param file
	 *            the file( in *.der format) that contains the private key
	 * @return the {@link PrivateKey} object
	 * 
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
	 * Reads the given {@link File}( in *.der format) with the given algorithm and returns the
	 * {@link PrivateKey} object.
	 *
	 * @param file
	 *            the file( in *.der format) that contains the private key
	 * @param algorithm
	 *            the algorithm
	 * @return the {@link PrivateKey} object
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
	 * Reads the given byte array with the default RSA algorithm and returns the {@link PrivateKey}
	 * object.
	 *
	 * @param privateKeyBytes
	 *            the byte array that contains the private key bytes
	 * @return the {@link PrivateKey} object
	 * 
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
	 * Reads the given byte array with the given algorithm and returns the {@link PrivateKey}
	 * object.
	 *
	 * @param privateKeyBytes
	 *            the byte array that contains the private key bytes
	 * @param algorithm
	 *            the algorithm for the {@link KeyFactory}
	 * @return the {@link PrivateKey} object
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
	 * Reads the given {@link File}( in *.pem format) with the default RSA algorithm and returns the
	 * {@link PrivateKey} object.
	 *
	 * @param file
	 *            the file( in *.pem format) that contains the private key
	 * @return the {@link PrivateKey} object
	 * 
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
	public static PrivateKey readPemPrivateKey(final File file) throws IOException,
		NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		final String privateKeyAsString = readPemFileAsBase64(file);
		final byte[] decoded = new Base64().decode(privateKeyAsString);
		return readPrivateKey(decoded);
	}

	/**
	 * Reads the given {@link File}( in *.pem format) with given algorithm and returns the
	 * {@link PrivateKey} object.
	 *
	 * @param file
	 *            the file( in *.pem format) that contains the private key
	 * @param algorithm
	 *            the algorithm
	 * @return the {@link PrivateKey} object
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	public static PrivateKey readPemPrivateKey(final File file, final String algorithm)
		throws IOException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException
	{
		final String privateKeyAsString = readPemFileAsBase64(file);
		return readPemPrivateKey(privateKeyAsString, algorithm);
	}

	/**
	 * Reads the given {@link String}( in *.pem format) with given algorithm and returns the
	 * {@link PrivateKey} object.
	 *
	 * @param privateKeyAsString
	 *            the private key as string( in *.pem format)
	 * @param algorithm
	 *            the algorithm
	 * @return the {@link PrivateKey} object
	 * 
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	public static PrivateKey readPemPrivateKey(final String privateKeyAsString,
		final String algorithm)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		final byte[] decoded = new Base64().decode(privateKeyAsString);
		return readPrivateKey(decoded, algorithm);
	}

	/**
	 * Read the private key from a pem file as base64 encoded {@link String} value.
	 *
	 * @param file
	 *            the file( in *.pem format) that contains the private key
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
	 * Constructs from the given root, parent directory and file name the file and reads the private
	 * key.
	 *
	 * @param root
	 *            the root directory of the parent directory
	 * @param directory
	 *            the parent directory of the private key file
	 * @param fileName
	 *            the file name of the file that contains the private key
	 * @return the private key
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             the no such provider exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static PrivateKey readPrivateKey(final File root, final String directory,
		final String fileName) throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException, IOException
	{

		final File privatekeyDir = new File(root, directory);
		final File privatekeyFile = new File(privatekeyDir, fileName);

		final PrivateKey privateKey = PrivateKeyReader.readPrivateKey(privatekeyFile);
		return privateKey;
	}

}
