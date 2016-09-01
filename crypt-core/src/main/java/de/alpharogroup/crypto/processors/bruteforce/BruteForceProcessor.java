/**
 * Copyright (C) 2015 Asterios Raptis
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
package de.alpharogroup.crypto.processors.bruteforce;

import java.util.Arrays;

/**
 * The Class BruteForceProcessor can process a brute force for find a password. For an example see
 * the junit test.
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
	 * Instantiates a new brute force processor.
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
				currentAttempt[index] = possiblesCharacters[Arrays.binarySearch(
					possiblesCharacters, currentAttempt[index]) + 1];
				break;
			}
		}
	}
}