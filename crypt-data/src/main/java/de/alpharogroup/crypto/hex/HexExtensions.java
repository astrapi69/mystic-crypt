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
package de.alpharogroup.crypto.hex;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import lombok.experimental.UtilityClass;

/**
 * The class {@link HexExtensions} provides methods for encode and decode hex encoded byte or char
 * arrays and {@link String} objects.
 */
@UtilityClass
public class HexExtensions
{
	/** A char array from the hexadecimal digits. */
	private static final char[] HEXADECIMAL_DIGITS = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
			'9', 'A', 'B', 'C', 'D', 'E', 'F' };

	/**
	 * Transform the given byte array that contains the binary data decoded to a String object. The
	 * given byte array comes usually from the {@link HexExtensions#decodeHex(char[])} method.
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

	/**
	 * Transform the given {@code byte array} to a hexadecimal {@link String} value.
	 *
	 * @param data
	 *            the byte array
	 * @return the new hexadecimal {@link String} value.
	 */
	public static String toHexString(final byte[] data)
	{
		return toHexString(data, true);
	}

	/**
	 * Transform the given {@code byte array} to a hexadecimal {@link String} value.
	 *
	 * @param data
	 *            the byte array
	 * @param lowerCase
	 *            the flag if the result shell be transform in lower case. If true the result is
	 * @return the new hexadecimal {@link String} value.
	 */
	public static String toHexString(final byte[] data, final boolean lowerCase)
	{
		final StringBuilder sb = new StringBuilder();
		sb.append(HexExtensions.encodeHex(data, lowerCase));
		return sb.toString();
	}

}
