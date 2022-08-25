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

import io.github.astrapi69.crypt.api.Encryptor;

/**
 * The class {@link CharacterSetEncryptor} is a simple {@link Encryptor} for encrypt a text with a
 * character set. The text is encrypted with the character set over the index.
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class CharacterSetEncryptor implements Encryptor<String, List<Integer>>
{

	/**
	 * The key
	 */
	private List<Character> key;

	/**
	 * Instantiates a new {@link CharacterSetEncryptor} with the given key
	 *
	 * @param key
	 *            The key
	 */
	public CharacterSetEncryptor(List<Character> key)
	{
		Objects.requireNonNull(key);
		this.key = key;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public List<Integer> encrypt(String toEncrypt) throws Exception
	{
		return CharacterSetCrypt.toIndexList(toEncrypt, key);
	}

}
