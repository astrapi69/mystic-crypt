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
package de.alpharogroup.crypto.obfuscation.rule;

/**
 * The enum {@link Operation} is intended for obfuscation operations. An example is if an operation
 * is uppercase then the letter will be transformed to uppercase.
 */
public enum Operation
{

	/** The lowercase. */
	LOWERCASE,
	/** The titlecase. */
	TITLECASE,
	/** The uppercase. */
	UPPERCASE;

	/**
	 * Operation on the given character.
	 *
	 * @param character
	 *            the character to operate
	 * @param operation
	 *            the operation
	 * @return the operated character
	 */
	public static Character operate(final char character, final Operation operation)
	{
		if (operation != null)
		{
			switch (operation)
			{
				case LOWERCASE :
					return Character.toLowerCase(character);
				case UPPERCASE :
					return Character.toUpperCase(character);
				case TITLECASE :
					return Character.toTitleCase(character);
			}
		}
		return operate(character, operation, false);
	}

	/**
	 * Operation on the given character.
	 *
	 * @param character
	 *            the character to operate
	 * @param operation
	 *            the operation
	 * @param reverse
	 *            the flag to reverse the operation
	 * @return the operated character
	 */
	public static Character operate(final char character, final Operation operation,
		final boolean reverse)
	{
		if (operation != null)
		{
			switch (operation)
			{
				case LOWERCASE :
					if (reverse)
					{
						return Character.toUpperCase(character);
					}
					return Character.toLowerCase(character);
				case UPPERCASE :
					if (reverse)
					{
						return Character.toLowerCase(character);
					}
					return Character.toUpperCase(character);
				case TITLECASE :
					if (reverse)
					{
						if (Character.isUpperCase(character))
						{
							return Character.toLowerCase(character);
						}
						else
						{
							return Character.toUpperCase(character);
						}
					}
					return Character.toTitleCase(character);
			}
		}
		return Character.valueOf(character);
	}
}
