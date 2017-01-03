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

import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.apache.commons.codec.binary.Base64;

import de.alpharogroup.crypto.hex.HexExtensions;
import lombok.experimental.UtilityClass;

/**
 * The class {@link PublicKeyExtensions}.
 */
@UtilityClass
public class PublicKeyExtensions
{

	/**
	 * Gets the key length of the given {@link PublicKey}.
	 *
	 * @param publicKey
	 *            the public key
	 * @return the key length
	 */
	public static int getKeyLength(final PublicKey publicKey)
	{
		int length = -1;
		if (publicKey == null)
		{
			return length;
		}
		if (publicKey instanceof RSAPublicKey)
		{
			length = ((RSAPublicKey)publicKey).getModulus().bitLength();
		}
		if (publicKey instanceof DSAPublicKey)
		{
			length = ((DSAPublicKey)publicKey).getParams().getP().bitLength();
		}
		if (publicKey instanceof ECPublicKey)
		{
			length = ((ECPublicKey)publicKey).getParams().getCurve().getField().getFieldSize();
		}

		return length;
	}

	/**
	 * Transform the given {@link PublicKey} to a hexadecimal {@link String} value.
	 *
	 * @param publicKey
	 *            the public key
	 * @return the new hexadecimal {@link String} value.
	 */
	public static String toHexString(final PublicKey publicKey)
	{
		return toHexString(publicKey, true);
	}

	/**
	 * Transform the given {@link PublicKey} to a base64 encoded {@link String} value.
	 *
	 * @param publicKey
	 *            the public key
	 * @return the base64 encoded {@link String} value.
	 */
	public static String toBase64(final PublicKey publicKey)
	{
		final byte[] encoded = publicKey.getEncoded();
		final String publicKeyAsBase64String = Base64.encodeBase64String(encoded);
		return publicKeyAsBase64String;
	}

	/**
	 * Transform the given {@link PublicKey} to a hexadecimal {@link String} value.
	 *
	 * @param publicKey
	 *            the public key
	 * @param lowerCase
	 *            the flag if the result shell be transform in lower case. If true the result is
	 * @return the new hexadecimal {@link String} value.
	 */
	public static String toHexString(final PublicKey publicKey, final boolean lowerCase)
	{
		final String hexString = HexExtensions.toHexString(publicKey.getEncoded(), lowerCase);
		return hexString;
	}
}
