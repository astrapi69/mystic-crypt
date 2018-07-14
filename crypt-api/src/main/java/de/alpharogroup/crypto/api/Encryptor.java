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
package de.alpharogroup.crypto.api;

/**
 * The generic functional interface {@link Encryptor} can encrypt an object of type &lt;T&gt; and
 * return the encrypted result as object of type &lt;R&gt;.
 *
 * @author Asterios Raptis
 * @version 1.0
 * @param <T>
 *            the generic type of the input to encrypt
 * @param <R>
 *            the generic type of the result
 */
public interface Encryptor<T, R>
{
	/**
	 * Encrypt the given object.
	 *
	 * @param toEncrypt
	 *            The object to encrypt.
	 * @return The encrypted object.
	 * @throws Exception
	 *             is thrown if encryption fails.
	 */
	public R encrypt(final T toEncrypt) throws Exception;

}
