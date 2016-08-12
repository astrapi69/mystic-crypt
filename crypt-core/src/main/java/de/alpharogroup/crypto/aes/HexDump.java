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

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

/**
 * The Class HexDump.
 */
public class HexDump
{
	/** A char array from the hexadecimal digits. */
	private static final char[] HEXADECIMAL_DIGITS = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
			'9', 'A', 'B', 'C', 'D', 'E', 'F' };

	/**
	 * Transform the given byte array that contains the binary data decoded to a String object. The
	 * given byte array comes usually from the {@link HexDump#decodeHex(char[])} method.
	 *
	 * @param data
	 *            the given byte array that contains the binary data decoded
	 * @return the decoded string
	 */
	public static String decodeHex(final byte[] data)
	{
		return new String(data);
	}

	/**
	 * Transform the given array of characters representing hexadecimal values into an array of
	 * bytes.
	 * 
	 * @param data
	 *            the array of characters
	 * @return A byte array that contains the binary data decoded from the given char array.
	 * @throws DecoderException
	 *             is thrown if an odd number or illegal of characters is supplied
	 */
	public static byte[] decodeHex(final char[] data) throws DecoderException
	{
		return Hex.decodeHex(data);
	}

	/**
	 * Transform the given array of characters representing hexadecimal values into a String object.
	 *
	 * @param data
	 *            the array of characters
	 * @return the decoded string
	 * @throws DecoderException
	 *             is thrown if an odd number or illegal of characters is supplied
	 */
	public static String decodeHexToString(final char[] data) throws DecoderException
	{
		return new String(Hex.decodeHex(data));
	}

	/**
	 * Transform the given array of bytes into an array of characters representing the hexadecimal
	 * values of each byte in order.
	 * 
	 * @param data
	 *            the byte array
	 * @return the resulted char array of the transformation.
	 */
	public static char[] encodeHex(final byte[] data)
	{
		return encodeHex(data, true);
	}

	/**
	 * Transform the given array of bytes into an array of characters representing the hexadecimal
	 * values of each byte in order.
	 * 
	 * @param data
	 *            the byte array
	 * @param lowerCase
	 *            the flag if the result shell be transform in lower case. If true the result is
	 *            lowercase otherwise uppercase.
	 * @return the resulted char array of the transformation.
	 */
	public static char[] encodeHex(final byte[] data, final boolean lowerCase)
	{
		return Hex.encodeHex(data, lowerCase);
	}

	/**
	 * Transform the given String into an array of characters representing the hexadecimal values of
	 * each byte in order.
	 * 
	 * @param data
	 *            the byte array
	 * @return the resulted char array of the transformation.
	 */
	public static char[] encodeHex(final String data)
	{
		return encodeHex(data.getBytes());
	}

	/**
	 * Transform the given {@code int} to a hexadecimal value.
	 * 
	 * @param i
	 *            the integer value to transform
	 * @return the char as a hexadecimal value.
	 */
	public static char toHex(final int i)
	{
		return HEXADECIMAL_DIGITS[i & 0xF];
	}

}