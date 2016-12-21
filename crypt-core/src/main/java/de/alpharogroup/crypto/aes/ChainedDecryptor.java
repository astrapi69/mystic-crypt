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
package de.alpharogroup.crypto.aes;

import de.alpharogroup.crypto.interfaces.GenericDecryptor;
import lombok.Builder;
import lombok.Getter;

/**
 * The Class ChainedDecryptor can take many {@code Decryptor} objects and decrypts the given string
 * with all the given {@code Decryptor} objects. The {@code Decryptor} objects must be in a reverse
 * order as they was given in the {@code ChainedEncryptor} object.
 */
@Builder
public class ChainedDecryptor implements GenericDecryptor<String, String>
{

	/** The decryptors. */
	@Getter
	private final GenericDecryptor<String, String>[] decryptors;

	/**
	 * Instantiates a new chained decryptor.
	 *
	 * @param decryptors
	 *            the decryptors
	 */
	@SafeVarargs
	public ChainedDecryptor(final GenericDecryptor<String, String>... decryptors)
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
		for (final GenericDecryptor<String, String> encryptor : decryptors)
		{
			result = encryptor.decrypt(result);
		}
		return result;
	}
}
