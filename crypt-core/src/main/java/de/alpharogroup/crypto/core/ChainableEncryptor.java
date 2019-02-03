/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto.core;

import de.alpharogroup.crypto.api.Encryptor;
import lombok.Getter;

/**
 * The class {@link ChainableEncryptor} can take many {@code Encryptor} objects and encrypts the
 * given string with all the given {@code Encryptor} objects.
 */
public abstract class ChainableEncryptor<T> implements Encryptor<T, T>
{

	/** The array with the {@code Encryptor} objects. */
	@Getter
	private final Encryptor<T, T>[] encryptors;

	/**
	 * Instantiates a new {@link ChainableEncryptor} object.
	 *
	 * @param encryptors
	 *            the {@code Encryptor} objects.
	 */
	@SafeVarargs
	public ChainableEncryptor(final Encryptor<T, T>... encryptors)
	{
		this.encryptors = encryptors;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public T encrypt(final T toEncrypt) throws Exception
	{
		T result = toEncrypt;
		for (final Encryptor<T, T> encryptor : encryptors)
		{
			result = encryptor.encrypt(result);
		}
		return result;
	}
}
