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
package de.alpharogroup.crypto.core;

import de.alpharogroup.crypto.api.Decryptor;

/**
 * The class {@link ChainableDecryptor} can take many {@code Decryptor} objects and decrypts the
 * given string with all the given {@code Decryptor} objects. The {@code Decryptor} objects must be
 * in a reverse order as they was given in the {@code ChainedEncryptor} object.
 */
public abstract class ChainableDecryptor<T> implements Decryptor<T, T>
{

	/** The decryptors. */
	private final Decryptor<T, T>[] decryptors;

	/**
	 * Instantiates a new {@link ChainableDecryptor} object.
	 *
	 * @param decryptors
	 *            the decryptors
	 */
	@SafeVarargs
	public ChainableDecryptor(final Decryptor<T, T>... decryptors)
	{
		this.decryptors = decryptors;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public T decrypt(final T encypted) throws Exception
	{
		T result = encypted;
		for (final Decryptor<T, T> encryptor : decryptors)
		{
			result = encryptor.decrypt(result);
		}
		return result;
	}

	public Decryptor<T, T>[] getDecryptors()
	{
		return this.decryptors;
	}
}
