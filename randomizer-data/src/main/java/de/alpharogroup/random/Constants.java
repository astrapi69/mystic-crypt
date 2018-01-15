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
package de.alpharogroup.random;

/**
 * The constant class {@link Constants} holds data for the characters to create random Strings like
 * passwords.
 *
 * @author Asterios Raptis
 */
public abstract class Constants
{

	/** All special Chars */
	public static final String SPECIALCHARS = "#@$%^&*?!";

	/** All digits. */
	public static final String NUMBERS = "0123456789";

	/** The alphabet-chars in lower case. */
	public static final String LOWCASECHARS = "abcdefghijklmnopqrstuvwxyz";

	/** The alphabet-chars in upper case. */
	public static final String UPPERCASECHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	/** Lowercase chars and numbers. */
	public static final String LCCHARSWN = LOWCASECHARS + NUMBERS;

	/** Lowercase chars and numbers. */
	public static final String LOWCASECHARS_WITH_NUMBERS = LCCHARSWN;

	/** Uppercase chars and numbers. */
	public static final String UCCHARSWN = UPPERCASECHARS + NUMBERS;

	/** Uppercase chars and numbers. */
	public static final String UPPERCASECHARS_WITH_NUMBERS = UCCHARSWN;

	/** Lowercase chars, numbers and special chars. */
	public static final String LCCHARSWNASC = LOWCASECHARS + NUMBERS + SPECIALCHARS;

	/** Lowercase chars, numbers and special chars. */
	public static final String LOWCASECHARS_WITH_NUMBERS_AND_SPECIALCHARS = LCCHARSWNASC;

	/** Lowercase chars, numbers and special chars. */
	public static final String UCCHARSWNASC = UPPERCASECHARS + NUMBERS + SPECIALCHARS;

	/** Lowercase chars, numbers and special chars. */
	public static final String UPPERCASECHARS_WITH_NUMBERS_AND_SPECIALCHARS = UCCHARSWNASC;

	/** Lower and uppercase chars and numbers. */
	public static final String LCUCCHARSWN = LOWCASECHARS + UPPERCASECHARS + NUMBERS;

	/** Lower and uppercase chars and numbers. */
	public static final String LOWCASECHARS_UPPERCASECHARS_WITH_NUMBERS = LCUCCHARSWN;

	/** Lower and uppercase chars with numbers and special chars. */
	public static final String LCUCCHARSWNASC = LOWCASECHARS + UPPERCASECHARS + NUMBERS
		+ SPECIALCHARS;

	/** Lower and uppercase chars with numbers and special chars. */
	public static final String LOWCASECHARS_UPPERCASECHARS_WITH_NUMBERS_AND_SPECIALCHARS = LCUCCHARSWNASC;

}
