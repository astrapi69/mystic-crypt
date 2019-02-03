/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto.key;

import java.io.IOException;
import java.io.StringWriter;
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

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.hex.HexExtensions;
import de.alpharogroup.crypto.key.reader.PemObjectReader;
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
	 * Gets the {@link KeySize} of the given {@link PrivateKey} or null if not found.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the {@link KeySize} of the given {@link PrivateKey} or null if not found.
	 */
	public static KeySize getKeySize(final PrivateKey privateKey)
	{
		int length = getKeyLength(privateKey);
		if (length == 1024)
		{
			return KeySize.KEYSIZE_1024;
		}
		if (length == 2048)
		{
			return KeySize.KEYSIZE_2048;
		}
		if (length == 4096)
		{
			return KeySize.KEYSIZE_4096;
		}
		if (length == 8192)
		{
			return KeySize.KEYSIZE_8192;
		}
		return null;
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
	 * Transform the given {@link PrivateKey} to a base64 encoded {@link String} value.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the new base64 encoded {@link String} value.
	 */
	public static String toBase64Binary(final PrivateKey privateKey)
	{
		final byte[] encoded = privateKey.getEncoded();
		final String privateKeyAsBase64String = DatatypeConverter.printBase64Binary(encoded);
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
	 * Transform the given private key that is in PKCS1 format and returns a {@link String} object
	 * in pem format.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the {@link String} object in pem format generated from the given private key.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static String toPemFormat(final PrivateKey privateKey) throws IOException
	{
		return PemObjectReader.toPemFormat(
			new PemObject(PrivateKeyReader.RSA_PRIVATE_KEY, toPKCS1Format(privateKey)));
	}

	/**
	 * Transform the given private key to PKCS#1 format and returns it as an byte array
	 *
	 * @param privateKey
	 *            the private key
	 * @return the byte array formatted in PKCS#1
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static byte[] toPKCS1Format(final PrivateKey privateKey) throws IOException
	{
		String keyFormat = privateKey.getFormat();
		if (KeyFormat.PKCS_8.getFormat().equals(keyFormat))
		{
			final byte[] encoded = privateKey.getEncoded();
			final PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(encoded);
			final ASN1Encodable asn1Encodable = privateKeyInfo.parsePrivateKey();
			final ASN1Primitive asn1Primitive = asn1Encodable.toASN1Primitive();
			final byte[] privateKeyPKCS1Formatted = asn1Primitive.getEncoded();
			return privateKeyPKCS1Formatted;
		}
		return privateKey.getEncoded();
	}

	/**
	 * Transform the given byte array(of private key in PKCS#1 format) to a PEM formatted
	 * {@link String}.
	 *
	 * @param privateKeyPKCS1Formatted
	 *            the byte array(of private key in PKCS#1 format)
	 * @return the String in PEM-Format
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	public static String fromPKCS1ToPemFormat(final byte[] privateKeyPKCS1Formatted)
		throws IOException
	{
		PemObject pemObject = new PemObject(PrivateKeyReader.RSA_PRIVATE_KEY,
			privateKeyPKCS1Formatted);
		StringWriter stringWriter = new StringWriter();
		PemWriter pemWriter = new PemWriter(stringWriter);
		pemWriter.writeObject(pemObject);
		pemWriter.close();
		String string = stringWriter.toString();
		return string;
	}


}
