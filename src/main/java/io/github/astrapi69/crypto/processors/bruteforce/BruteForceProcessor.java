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
package io.github.astrapi69.crypto.processors.bruteforce;

import java.util.Arrays;

/**
 * The class {@link BruteForceProcessor} can process a brute force for find a password. For an
 * example see the unit test.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public class BruteForceProcessor
{

	/** The possibles characters. */
	private final char[] possiblesCharacters;
	/** The current attempt. */
	private char[] currentAttempt;

	/**
	 * Instantiates a new {@link BruteForceProcessor} object.
	 *
	 * @param possiblesCharacters
	 *            the possibles characters
	 * @param attemptLength
	 *            the attempt length
	 */
	public BruteForceProcessor(final char[] possiblesCharacters, final int attemptLength)
	{
		this.possiblesCharacters = possiblesCharacters;
		this.currentAttempt = new char[attemptLength];
		Arrays.fill(currentAttempt, possiblesCharacters[0]);
	}

	/**
	 * Gets the current attempt.
	 *
	 * @return the current attempt
	 */
	public String getCurrentAttempt()
	{
		return new String(currentAttempt);
	}

	/**
	 * Increment.
	 */
	public void increment()
	{
		int index = currentAttempt.length - 1;
		while (0 <= index)
		{
			if (currentAttempt[index] == possiblesCharacters[possiblesCharacters.length - 1])
			{
				if (index == 0)
				{
					currentAttempt = new char[currentAttempt.length + 1];
					Arrays.fill(currentAttempt, possiblesCharacters[0]);
					break;
				}
				else
				{
					currentAttempt[index] = possiblesCharacters[0];
					index--;
				}
			}
			else
			{
				currentAttempt[index] = possiblesCharacters[Arrays.binarySearch(possiblesCharacters,
					currentAttempt[index]) + 1];
				break;
			}
		}
	}
}
