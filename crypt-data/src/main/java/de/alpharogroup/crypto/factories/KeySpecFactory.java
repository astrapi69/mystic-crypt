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
package de.alpharogroup.crypto.factories;

import java.security.spec.KeySpec;

import javax.crypto.spec.PBEKeySpec;

import de.alpharogroup.crypto.CryptConst;
import lombok.experimental.UtilityClass;

/**
 * The factory class {@link KeySpecFactory} holds methods for creating {@link KeySpec} objects.
 */
@UtilityClass
public class KeySpecFactory
{

	/**
	 * Factory method for creating a new {@link PBEKeySpec} from the given private key.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the new {@link PBEKeySpec} from the given private key.
	 */
	public static KeySpec newPBEKeySpec(final String privateKey)
	{
		if (privateKey == null)
		{
			return new PBEKeySpec(CryptConst.PRIVATE_KEY.toCharArray());
		}
		return new PBEKeySpec(privateKey.toCharArray());
	}

	/**
	 * Factory method for creating a new {@link PBEKeySpec} from the given private key.
	 *
	 * @param privateKey
	 *            the private key
	 * @param salt
	 *            the salt
	 * @param iterationCount
	 *            the iteration count
	 * @return the new {@link PBEKeySpec} from the given private key.
	 */
	public static KeySpec newPBEKeySpec(final String privateKey, final byte[] salt,
		final int iterationCount)
	{
		if (privateKey == null)
		{
			return new PBEKeySpec(CryptConst.PRIVATE_KEY.toCharArray(), salt, iterationCount);
		}
		return new PBEKeySpec(privateKey.toCharArray(), salt, iterationCount);
	}

}
