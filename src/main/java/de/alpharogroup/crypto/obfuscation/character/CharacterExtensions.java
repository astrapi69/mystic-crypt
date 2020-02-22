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
package de.alpharogroup.crypto.obfuscation.character;

/**
 * The class {@link CharacterExtensions} provides utility methods for {@link Character} objects
 */
public final class CharacterExtensions
{

	/**
	 * Compares this {@code Character} to another {@code Character}, ignoring case considerations.
	 *
	 * @param character
	 *            the character
	 * @param another
	 *            the other
	 * @return true, if successful
	 */
	public static boolean equalsIgnoreCase(Character character, Character another)
	{
		if (character == null && another == null)
		{
			return true;
		}
		if (character == null && another != null || character != null && another == null)
		{
			return false;
		}
		return Character.valueOf(Character.toLowerCase(character.charValue()))
			.equals(Character.valueOf(Character.toLowerCase(another.charValue())));

	}

	private CharacterExtensions()
	{
	}
}
