/**
 * Copyright (C) 2015 Asterios Raptis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.alpharogroup.crypto.factories;

import java.security.spec.KeySpec;

import javax.crypto.spec.PBEKeySpec;

import de.alpharogroup.crypto.CryptConst;


/**
 * A factory for creating KeySpec objects.
 */
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
