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
package io.github.astrapi69.mystic.crypt.simple;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * The class {@link CharacterSetCrypt} provides algorithms for encrypt a text with a character set.
 * The text is encrypted with the character set over the index. The decryption builds the text over
 * the indexes and the character set. So the character set is the key element in this encryption
 * method.
 */
public final class CharacterSetCrypt
{

	private CharacterSetCrypt()
	{
	}

	/**
	 * To index list.
	 *
	 * @param text
	 *            the text
	 * @param characters
	 *            the characters
	 * @return the list
	 */
	public static List<Integer> toIndexList(final String text, final List<Character> characters)
	{
		Objects.requireNonNull(text);
		Objects.requireNonNull(characters);
		char[] chars = text.toCharArray();
		List<Integer> integerList = new ArrayList<>();
		for (char c : chars)
		{
			integerList.add(characters.indexOf(Character.valueOf(c)));
		}
		return integerList;
	}

	/**
	 * To text.
	 *
	 * @param integerList
	 *            the integer list
	 * @param characters
	 *            the characters
	 * @return the string
	 */
	public static String toText(final List<Integer> integerList, final List<Character> characters)
	{
		Objects.requireNonNull(integerList);
		Objects.requireNonNull(characters);
		StringBuilder sb = new StringBuilder();
		for (int index : integerList)
		{
			sb.append(characters.get(index));
		}
		return sb.toString();
	}

}
