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

import java.io.Writer;
import java.util.Arrays;

/**
 * Collects what is written into a character array that can be overwritten afterwards, including
 * every array it outgrew on the way (mystic-crypt-ui#294).
 * <p>
 * {@link java.io.CharArrayWriter} would do the collecting, and it is the reason this class exists:
 * when it runs out of room it allocates a bigger array, copies, and drops the old one. For a secret
 * of any size that leaves a chain of arrays behind, each holding the beginning of the plaintext,
 * and none of them reachable to be overwritten. Growing is exactly the moment a buffer full of
 * secrets must be wiped, so growing is what this class does differently.
 */
public final class WipingCharWriter extends Writer
{

	private char[] buffer;

	private int written;

	/**
	 * Creates a writer with room for the given number of characters before it has to grow
	 *
	 * @param initialCapacity
	 *            the initial capacity, at least one
	 */
	public WipingCharWriter(final int initialCapacity)
	{
		buffer = new char[Math.max(1, initialCapacity)];
	}

	@Override
	public void write(final char[] characters, final int offset, final int length)
	{
		ensureRoomFor(length);
		System.arraycopy(characters, offset, buffer, written, length);
		written += length;
	}

	@Override
	public void write(final int character)
	{
		ensureRoomFor(1);
		buffer[written++] = (char)character;
	}

	@Override
	public void write(final String characters, final int offset, final int length)
	{
		ensureRoomFor(length);
		characters.getChars(offset, offset + length, buffer, written);
		written += length;
	}

	@Override
	public void flush()
	{
	}

	@Override
	public void close()
	{
	}

	/**
	 * What was written so far, in a new array the caller owns and is expected to overwrite when it
	 * is done with it
	 *
	 * @return the characters written
	 */
	public char[] toCharArray()
	{
		return Arrays.copyOf(buffer, written);
	}

	/** Overwrites everything written so far and starts again from empty */
	public void wipe()
	{
		Arrays.fill(buffer, '\0');
		written = 0;
	}

	private void ensureRoomFor(final int length)
	{
		if (written + length <= buffer.length)
		{
			return;
		}
		int capacity = Math.max(buffer.length * 2, written + length);
		char[] grown = new char[capacity];
		System.arraycopy(buffer, 0, grown, 0, written);
		// the array being left behind holds the beginning of the secret; it is dropped only
		// after it has been overwritten
		Arrays.fill(buffer, '\0');
		buffer = grown;
	}
}
