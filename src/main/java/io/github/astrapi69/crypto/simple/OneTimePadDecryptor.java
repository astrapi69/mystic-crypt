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
package io.github.astrapi69.crypto.simple;

import io.github.astrapi69.check.Argument;
import io.github.astrapi69.crypt.api.ByteArrayDecryptor;

/**
 * The class {@link OneTimePadDecryptor} is a simple {@link ByteArrayDecryptor} for the one time pad
 * algorithm
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class OneTimePadDecryptor implements ByteArrayDecryptor
{

	/**
	 * The key
	 */
	private final byte[] key;

	/**
	 * Instantiates a new {@link OneTimePadDecryptor} with the given key
	 *
	 * @param key
	 *            The key
	 */
	public OneTimePadDecryptor(byte[] key)
	{
		Argument.notEmpty(key, "key");
		this.key = key;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] decrypt(byte[] encrypted) throws Exception
	{
		return SimpleCrypt.oneTimePadCrypt(this.key, encrypted);
	}
}
