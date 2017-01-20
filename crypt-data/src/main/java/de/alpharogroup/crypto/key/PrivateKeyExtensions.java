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

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.List;

import org.apache.commons.codec.binary.Base64;

import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.hex.HexExtensions;
import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import lombok.experimental.UtilityClass;

/**
 * The class {@link PrivateKeyExtensions}.
 */
@UtilityClass
public class PrivateKeyExtensions
{

	/**
	 * Gets the key length of the given {@link PrivateKey}.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the key length
	 */
	public static int getKeyLength(final PrivateKey privateKey)
	{
		int length = -1;
		if (privateKey == null)
		{
			return length;
		}
		if (privateKey instanceof RSAPrivateKey)
		{
			length = ((RSAPrivateKey)privateKey).getModulus().bitLength();
		}
		if (privateKey instanceof DSAPrivateKey)
		{
			length = ((DSAPrivateKey)privateKey).getParams().getQ().bitLength();
		}
		if (privateKey instanceof ECPrivateKey)
		{
			length = ((ECPrivateKey)privateKey).getParams().getCurve().getField().getFieldSize();
		}
		return length;
	}

	/**
	 * Transform the given {@link PrivateKey} to a hexadecimal {@link String} value.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the new hexadecimal {@link String} value.
	 */
	public static String toHexString(final PrivateKey privateKey)
	{
		return toHexString(privateKey, true);
	}

	/**
	 * Transform the given {@link PrivateKey} to a hexadecimal {@link String} value.
	 *
	 * @param privateKey
	 *            the private key
	 * @param lowerCase
	 *            the flag if the result shell be transform in lower case. If true the result is
	 * @return the new hexadecimal {@link String} value.
	 */
	public static String toHexString(final PrivateKey privateKey, final boolean lowerCase)
	{
		final String hexString = HexExtensions.toHexString(privateKey.getEncoded(), lowerCase);
		return hexString;
	}

	/**
	 * Transform the given {@link PrivateKey} to a base64 encoded {@link String} value.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the new base64 encoded {@link String} value.
	 */
	public static String toBase64(final PrivateKey privateKey)
	{
		final byte[] encoded = privateKey.getEncoded();
		final String privateKeyAsBase64String = Base64.encodeBase64String(encoded);
		return privateKeyAsBase64String;
	}

	/**
	 * Generate the corresponding {@link PublicKey} object from the given {@link PrivateKey} object.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the corresponding {@link PublicKey} object or null if generation failed.
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 * @throws InvalidKeySpecException
	 *             the invalid key spec exception
	 */
	public static PublicKey generatePublicKey(final PrivateKey privateKey)
		throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		if (privateKey instanceof RSAPrivateKey)
		{
			final RSAPrivateCrtKey privk = (RSAPrivateCrtKey)privateKey;
			final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(privk.getModulus(),
				privk.getPublicExponent());

			final KeyFactory keyFactory = KeyFactory
				.getInstance(KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
			final PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
			return publicKey;
		}
		return null;
	}



	/**
	 * Transform the public key in pem format.
	 *
	 * @param publicKey
	 *            the public key
	 * @return the public key in pem format
	 */
	public static String toPemFormat(final PrivateKey privateKey)
	{
		final String publicKeyAsBase64String =  toBase64(privateKey);
		final List<String> parts = PublicKeyExtensions.splitByFixedLength(publicKeyAsBase64String, 64);

		final StringBuilder sb = new StringBuilder();
		sb.append(PrivateKeyReader.BEGIN_RSA_PRIVATE_KEY_PREFIX);
		for(final String part : parts) {
			sb.append(part);
			sb.append(System.lineSeparator());
		}
		sb.append(PrivateKeyReader.END_RSA_PRIVATE_KEY_SUFFIX);
		sb.append(System.lineSeparator());
		return sb.toString();
	}

}
