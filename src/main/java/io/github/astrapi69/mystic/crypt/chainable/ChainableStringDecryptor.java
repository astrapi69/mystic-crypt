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
package io.github.astrapi69.mystic.crypt.chainable;

import io.github.astrapi69.crypt.api.Decryptor;
import io.github.astrapi69.mystic.crypt.core.ChainableDecryptor;

/**
 * The class {@link ChainableStringDecryptor} can take many {@code Decryptor} objects and decrypts
 * the given string with all the given {@code Decryptor} objects. The {@code Decryptor} objects must
 * be in a reverse order as they was given in the {@code ChainedEncryptor} object. For an example
 * see the unit test.
 */
public class ChainableStringDecryptor extends ChainableDecryptor<String>
{

	/**
	 * Instantiates a new {@link ChainableStringDecryptor} object.
	 *
	 * @param decryptors
	 *            the decryptors
	 */
	// [varargs] javac warns because the varargs array reference is passed on instead of only its
	// elements being read. It cannot see that the callee is safe. This constructor merely forwards
	// the array to the @SafeVarargs constructor of ChainableDecryptor; it neither writes into the
	// array, nor stores it, nor returns it, so it introduces no aliasing of its own.
	@SafeVarargs
	@SuppressWarnings("varargs")
	public ChainableStringDecryptor(final Decryptor<String, String>... decryptors)
	{
		super(decryptors);
	}

}
