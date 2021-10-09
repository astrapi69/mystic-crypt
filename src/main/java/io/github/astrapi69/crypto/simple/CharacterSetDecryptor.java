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

import java.util.List;
import java.util.Objects;

import io.github.astrapi69.crypto.api.Decryptor;

/**
 * The class {@link CharacterSetDecryptor} is a simple {@link Decryptor} for decrypt a integer list
 * with a character set. The decryption builds the text over the indexes and the character set. So
 * the character set is the key element in this encryption and decryption algorithm
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class CharacterSetDecryptor implements Decryptor<List<Integer>, String>
{

	/**
	 * The key
	 */
	private List<Character> key;

	/**
	 * Instantiates a new {@link CharacterSetDecryptor} with the given key
	 *
	 * @param key
	 *            The key
	 */
	public CharacterSetDecryptor(List<Character> key)
	{
		Objects.requireNonNull(key);
		this.key = key;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String decrypt(List<Integer> encrypted) throws Exception
	{
		return CharacterSetCrypt.toText(encrypted, key);
	}

}
