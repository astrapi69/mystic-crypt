/**
 * Copyright (C) 2007 Asterios Raptis
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
package de.alpharogroup.crypto.aes;

import lombok.Builder;
import lombok.Getter;
import de.alpharogroup.crypto.interfaces.Encryptor;

/**
 * The Class ChainedEncryptor can take many {@code Encryptor} objects and encrypts the given string
 * with all the given {@code Encryptor} objects.
 */
@Builder
public class ChainedEncryptor implements Encryptor
{

	/** The encryptors. */
	@Getter
	private final Encryptor[] encryptors;

	/**
	 * Instantiates a new chained encryptor.
	 *
	 * @param encryptors
	 *            the encryptors
	 */
	public ChainedEncryptor(final Encryptor... encryptors)
	{
		this.encryptors = encryptors;
	}

	/**
	 * Encrypt the given String.
	 * 
	 * @param string
	 *            The String to encrypt.
	 * @return The encrypted String.
	 * @throws Exception
	 *             is thrown if encryption fails.
	 */
	@Override
	public String encrypt(final String string) throws Exception
	{
		String result = string;
		for (final Encryptor encryptor : encryptors)
		{
			result = encryptor.encrypt(result);
		}
		return result;
	}
}
