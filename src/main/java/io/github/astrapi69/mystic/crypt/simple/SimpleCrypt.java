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
package io.github.astrapi69.mystic.crypt.simple;

/**
 * The class {@link SimpleCrypt} is an utility class for the use of encrypt or decrypt information.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public final class SimpleCrypt
{

	private SimpleCrypt()
	{
	}

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
	 * Encrypt and decrypt with the simple one time pad algorithm
	 *
	 * @param simpleKey
	 *            the byte array that holds the key
	 * @param message
	 *            the byte array with the data to encrypt or decrypt
	 * @return The encrypted or decrypted byte array
	 */
	public static byte[] oneTimePadCrypt(byte[] simpleKey, byte[] message)
	{
		final byte[] encoded = new byte[message.length];
		for (int index = 0; index < message.length; index++)
		{
			int keyIndex = index;
			// prevent that key length is smaller than the length of the given byte array
			// to encrypt or decrypt
			if (index >= simpleKey.length)
			{
				keyIndex = message.length % (simpleKey.length - 1);
			}
			encoded[index] = (byte)(message[index] ^ simpleKey[keyIndex]);
		}
		return encoded;
	}

}
