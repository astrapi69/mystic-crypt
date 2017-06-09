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
package de.alpharogroup.crypto.key;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.key.reader.PemObjectReader;
import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.crypto.key.reader.PublicKeyReader;
import de.alpharogroup.crypto.provider.SecurityProvider;
import lombok.experimental.UtilityClass;

/**
 * The class {@link KeyExtensions} holds utility methods for read public and private keys from
 * files.
 *
 * @deprecated Use instead the reader classes {@link PublicKeyReader}, {@link PrivateKeyReader} and
 *             {@link PemObjectReader}.
 */
@UtilityClass
@Deprecated
public class KeyExtensions
{

	/** The Constant AES_KEY_LENGTH. */
	public static final int AES_KEY_LENGTH = 256;

	/** The Constant END_CERTIFICATE_SUFFIX. */
	public static final String END_CERTIFICATE_SUFFIX = "-----END CERTIFICATE-----";

	/** The Constant BEGIN_CERTIFICATE_PREFIX. */
	public static final String BEGIN_CERTIFICATE_PREFIX = "-----BEGIN CERTIFICATE-----\n";

	/** The Constant END_PUBLIC_KEY_SUFFIX. */
	public static final String END_PUBLIC_KEY_SUFFIX = "-----END PUBLIC KEY-----";

	/** The Constant BEGIN_PUBLIC_KEY_PREFIX. */
	public static final String BEGIN_PUBLIC_KEY_PREFIX = "-----BEGIN PUBLIC KEY-----\n";

	/** The Constant END_PRIVATE_KEY_SUFFIX. */
	public static final String END_PRIVATE_KEY_SUFFIX = "-----END PRIVATE KEY-----";

	/** The Constant BEGIN_PRIVATE_KEY_PREFIX. */
	public static final String BEGIN_PRIVATE_KEY_PREFIX = "-----BEGIN PRIVATE KEY-----";

	/** The Constant END_RSA_PRIVATE_KEY_SUFFIX. */
	public static final String END_RSA_PRIVATE_KEY_SUFFIX = "\n-----END RSA PRIVATE KEY-----";

	/** The Constant BEGIN_RSA_PRIVATE_KEY_PREFIX. */
	public static final String BEGIN_RSA_PRIVATE_KEY_PREFIX = "-----BEGIN RSA PRIVATE KEY-----\n";

	/**
	 * Read public key.
	 *
	 * @param publicKeyBytes
	 *            the public key bytes
	 * @param securityProvider
	 *            the security provider
	 * @return the public key
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	public static PublicKey readPublicKey(final byte[] publicKeyBytes,
		final SecurityProvider securityProvider)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		return readPublicKey(publicKeyBytes, securityProvider.name());
	}

	/**
	 * Read public key.
	 *
	 * @param publicKeyBytes
	 *            the public key bytes
	 * @param provider
	 *            the provider
	 * @return the public key
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	public static PublicKey readPublicKey(final byte[] publicKeyBytes, final String provider)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
		final KeyFactory keyFactory = KeyFactory
			.getInstance(KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		final PublicKey publicKey = keyFactory.generatePublic(keySpec);
		return publicKey;
	}

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
		final byte[] keyBytes = Files.readAllBytes(file.toPath());
		return readPrivateKey(keyBytes, "BC");
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
		final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		final KeyFactory keyFactory = KeyFactory
			.getInstance(KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		final PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
		return privateKey;
	}

}
