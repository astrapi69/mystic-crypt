/**
 * Copyright (C) 2007 Asterios Raptis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.alpharogroup.random;

/**
 * A constant class for the characters to create random Strings like passwords.
 * 
 * @author Asterios.Raptis@web.de
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

	/** Uppercase chars and numbers. */
	public static final String UCCHARSWN = UPPERCASECHARS + NUMBERS;

	/** Lowercase chars, numbers and special chars. */
	public static final String LCCHARSWNASC = LOWCASECHARS + NUMBERS + SPECIALCHARS;

	/** Lowercase chars, numbers and special chars. */
	public static final String UCCHARSWNASC = UPPERCASECHARS + NUMBERS + SPECIALCHARS;

	/** Lower and uppercase chars and numbers. */
	public static final String LCUCCHARSWN = LOWCASECHARS + UPPERCASECHARS + NUMBERS;

}
