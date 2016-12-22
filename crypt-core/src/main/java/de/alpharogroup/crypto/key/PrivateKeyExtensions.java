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

import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;

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

}
