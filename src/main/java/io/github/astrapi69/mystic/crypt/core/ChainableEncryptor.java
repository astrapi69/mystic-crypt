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
package io.github.astrapi69.mystic.crypt.core;

import io.github.astrapi69.crypt.api.Encryptor;

/**
 * The class {@link ChainableEncryptor} can take many {@code Encryptor} objects and encrypts the
 * given string with all the given {@code Encryptor} objects.
 *
 * @param <T>
 *            the generic type of the value that is encrypted. Because every {@code Encryptor} in
 *            the chain consumes the output of its predecessor, the encrypted and the decrypted type
 *            have to be the same
 */
public abstract class ChainableEncryptor<T> implements Encryptor<T, T>
{

	/** The array with the {@code Encryptor} objects. */
	private final Encryptor<T, T>[] encryptors;

	/**
	 * Instantiates a new {@link ChainableEncryptor} object.
	 *
	 * @param encryptors
	 *            the {@code Encryptor} objects.
	 */
	// [varargs] javac warns because the varargs array reference itself (not just its elements) is
	// used here. The assertion behind @SafeVarargs holds for this class: it never writes into the
	// array, never widens its element type and only ever reads elements as Encryptor<T, T>, so it
	// cannot pollute the heap on its own. The array does stay reachable through getEncryptors() -
	// the same trade-off the JDK accepts for Arrays.asList(T...) - so a caller that already did an
	// unchecked generic array creation can still alias it; handing back a defensive copy would be
	// an observable API change and is deliberately not done in this release.
	@SafeVarargs
	@SuppressWarnings("varargs")
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

	/**
	 * Get the array of the encryptors
	 *
	 * @return the array of the encryptors
	 */
	public Encryptor<T, T>[] getEncryptors()
	{
		return this.encryptors;
	}
}
