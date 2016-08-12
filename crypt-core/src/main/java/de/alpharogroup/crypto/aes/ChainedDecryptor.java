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
package de.alpharogroup.crypto.aes;

import lombok.Builder;
import lombok.Getter;
import de.alpharogroup.crypto.interfaces.Decryptor;

/**
 * The Class ChainedDecryptor can take many {@code Decryptor} objects and decrypts the given string
 * with all the given {@code Decryptor} objects. The {@code Decryptor} objects must be in a reverse
 * order as they was given in the {@code ChainedEncryptor} object.
 */
@Builder
public class ChainedDecryptor implements Decryptor
{

	/** The decryptors. */
	@Getter
	private final Decryptor[] decryptors;

	/**
	 * Instantiates a new chained decryptor.
	 *
	 * @param decryptors
	 *            the decryptors
	 */
	public ChainedDecryptor(final Decryptor... decryptors)
	{
		this.decryptors = decryptors;
	}

	/**
	 * Decrypt the given encrypted String.
	 * 
	 * @param encypted
	 *            The String to decrypt.
	 * @return The decrypted String
	 * @throws Exception
	 *             is thrown if decryption fails.
	 */
	@Override
	public String decrypt(final String encypted) throws Exception
	{
		String result = encypted;
		for (final Decryptor encryptor : decryptors)
		{
			result = encryptor.decrypt(result);
		}
		return result;
	}
}
