/*
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
package io.github.astrapi69.mystic.crypt.secret;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Buffers that hold something secret, and the two conversions that must not go through a
 * {@link String} on the way (mystic-crypt-ui#294).
 * <p>
 * A String cannot be overwritten. It lives until the collector reaches it, and after that its
 * characters are still in the memory it used until something else happens to write there. That is
 * the whole reason a passphrase is taken as a character array - and it was given away at every
 * point where one of them was converted, because {@code new String(chars).getBytes(UTF_8)} leaves
 * an unwipeable copy behind for the sake of two method calls.
 * <p>
 * So the conversions here go through {@link java.nio.charset.Charset} directly, and the buffer the
 * encoder or decoder used is overwritten before it is dropped.
 */
public final class SecretBuffers
{

	private SecretBuffers()
	{
	}

	/**
	 * Overwrites the given characters. Null and empty are accepted and do nothing
	 *
	 * @param chars
	 *            the characters to overwrite
	 */
	public static void wipe(final char[] chars)
	{
		if (chars != null)
		{
			Arrays.fill(chars, '\0');
		}
	}

	/**
	 * Overwrites the given bytes. Null and empty are accepted and do nothing
	 *
	 * @param bytes
	 *            the bytes to overwrite
	 */
	public static void wipe(final byte[] bytes)
	{
		if (bytes != null)
		{
			Arrays.fill(bytes, (byte)0);
		}
	}

	/**
	 * Encodes the given characters as UTF-8, without a {@link String} in between. The characters
	 * handed over are read, not modified: whoever owns them decides when they are overwritten
	 *
	 * @param chars
	 *            the characters
	 * @return the UTF-8 bytes
	 */
	public static byte[] toUtf8(final char[] chars)
	{
		ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
		byte[] bytes = new byte[encoded.remaining()];
		encoded.get(bytes);
		// the encoder sizes its buffer generously and it still holds what was encoded
		wipeBackingArrayOf(encoded);
		return bytes;
	}

	/**
	 * Decodes the given UTF-8 bytes into characters, without a {@link String} in between. The bytes
	 * handed over are read, not modified
	 *
	 * @param bytes
	 *            the UTF-8 bytes
	 * @return the characters
	 */
	public static char[] fromUtf8(final byte[] bytes)
	{
		CharBuffer decoded = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(bytes));
		char[] chars = new char[decoded.remaining()];
		decoded.get(chars);
		wipeBackingArrayOf(decoded);
		return chars;
	}

	/**
	 * Wipes the array a buffer sits on, when it has one it will let go of.
	 * <p>
	 * The guard is the whole method: {@code array()} throws on a read-only or direct buffer, and
	 * while {@code UTF_8.encode} and {@code UTF_8.decode} return heap buffers today, nothing in
	 * their contract says they must. Package-visible rather than private so that the refusing case
	 * can be tested at all - this library gates branch coverage at 100% deliberately, and a guard
	 * nothing can reach is a guard nothing proves (docs/TESTING.md).
	 *
	 * @param buffer
	 *            the buffer whose backing array is to be overwritten
	 */
	static void wipeBackingArrayOf(final ByteBuffer buffer)
	{
		if (buffer.hasArray())
		{
			wipe(buffer.array());
		}
	}

	/**
	 * Wipes the array a buffer sits on, when it has one it will let go of
	 *
	 * @param buffer
	 *            the buffer whose backing array is to be overwritten
	 * @see #wipeBackingArrayOf(ByteBuffer)
	 */
	static void wipeBackingArrayOf(final CharBuffer buffer)
	{
		if (buffer.hasArray())
		{
			wipe(buffer.array());
		}
	}
}
