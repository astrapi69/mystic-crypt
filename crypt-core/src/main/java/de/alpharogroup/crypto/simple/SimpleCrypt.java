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
package de.alpharogroup.crypto.simple;

/**
 * Utility class for the use of encrypt or decrypt information.
 * 
 * @version 1.0
 * @author Asterios Raptis
 */
public final class SimpleCrypt
{

	/**
	 * Decrypt the given String.
	 * 
	 * @param toDecode
	 *            The String to decrypt.
	 * @return The decrypted String.
	 */
	public static String decode(final String toDecode)
	{
		return decode(toDecode, 28);
	}

	/**
	 * Decrypt the given String.
	 * 
	 * @param toDecode
	 *            The String to decrypt.
	 * @param relocate
	 *            How much places to switch.
	 * @return The decrypted String.
	 */
	public static String decode(final String toDecode, final int relocate)
	{
		final StringBuffer sb = new StringBuffer();
		final char[] encrypt = toDecode.toCharArray();
		final int arraylength = encrypt.length;
		for (int i = 0; i < arraylength; i++)
		{
			final char a = (char)(encrypt[i] - relocate);
			sb.append(a);
		}
		return sb.toString().trim();
	}

	/**
	 * Encrypt the given String.
	 * 
	 * @param secret
	 *            The String to encrypt.
	 * @return The encrypted String.
	 */
	public static String encode(final String secret)
	{
		return encode(secret, 28);
	}

	/**
	 * Encrypt the given String.
	 * 
	 * @param secret
	 *            The String to encrypt.
	 * @param relocate
	 *            How much places to switch.
	 * @return The encrypted String.
	 */
	public static String encode(final String secret, final int relocate)
	{
		final StringBuffer sb = new StringBuffer();
		final char[] encrypt = secret.toCharArray();
		final int arraylength = encrypt.length;
		for (int i = 0; i < arraylength; i++)
		{
			final char a = (char)(encrypt[i] + relocate);
			sb.append(a);
		}
		return sb.toString().trim();
	}

	/**
	 * Private constructor. To avoid creating instances.
	 */
	private SimpleCrypt()
	{
	}

}
