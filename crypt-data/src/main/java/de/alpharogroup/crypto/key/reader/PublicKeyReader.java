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
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;

import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import lombok.experimental.UtilityClass;


/**
 * The class {@link PublicKeyReader} is a utility class for reading public keys.
 */
@UtilityClass
public class PublicKeyReader
{

	/** The Constant END_PUBLIC_KEY_SUFFIX. */
	public static final String END_PUBLIC_KEY_SUFFIX = "-----END PUBLIC KEY-----";

	/** The Constant BEGIN_PUBLIC_KEY_PREFIX. */
	public static final String BEGIN_PUBLIC_KEY_PREFIX = "-----BEGIN PUBLIC KEY-----\n";

	/**
	 * Read public key.
	 *
	 * @param file
	 *            the file
	 * @return the public key
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
	public static PublicKey readPublicKey(final File file) throws IOException,
		NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		final byte[] keyBytes = Files.readAllBytes(file.toPath());
		return readPublicKey(keyBytes);
	}

	/**
	 * Read public key.
	 *
	 * @param publicKeyBytes
	 *            the public key bytes
	 * @return the public key
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	public static PublicKey readPublicKey(final byte[] publicKeyBytes)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		return readPublicKey(publicKeyBytes, KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
	}

	/**
	 * Read public key.
	 *
	 * @param publicKeyBytes
	 *            the public key bytes
	 * @param algorithm
	 *            the algorithm for the {@link KeyFactory}
	 * @return the public key
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	public static PublicKey readPublicKey(final byte[] publicKeyBytes, final String algorithm)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
		final KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		final PublicKey publicKey = keyFactory.generatePublic(keySpec);
		return publicKey;
	}

	/**
	 * reads a public key from a file.
	 *
	 * @param file
	 *            the file
	 * @return the public key
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
	public static PublicKey readPemPublicKey(final File file) throws IOException,
		NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		final String publicKeyAsString = readPemFileAsBase64(file);
		final byte[] decoded = Base64.decodeBase64(publicKeyAsString);
		return readPublicKey(decoded);
	}

	/**
	 * Read the public key from a pem file as base64 encoded {@link String} value.
	 *
	 * @param file
	 *            the file in pem format that contains the public key.
	 * @return the base64 encoded {@link String} value.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static String readPemFileAsBase64(final File file) throws IOException
	{
		final byte[] keyBytes = Files.readAllBytes(file.toPath());
		final String publicKeyAsBase64String = new String(keyBytes)
			.replace(BEGIN_PUBLIC_KEY_PREFIX, "").replace(END_PUBLIC_KEY_SUFFIX, "");
		return publicKeyAsBase64String;
	}

}
