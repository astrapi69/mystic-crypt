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
package de.alpharogroup.crypto.processors.wordlist;

import java.util.List;

import lombok.Getter;
import lombok.Setter;
import de.alpharogroup.check.Check;

public class WordlistsProcessor
{
	private final List<String> words;
	private int currentIndex;
	/** The password to check against it. */
	@Getter
	@Setter
	private String toCheckAgainst;

	public WordlistsProcessor(final List<String> words)
	{
		this.words = words;
		this.currentIndex = 0;
	}

	public WordlistsProcessor(final List<String> words, final String toCheckAgainst)
	{
		Check.get().notNull(toCheckAgainst, "toCheckAgainst")
			.notEmpty(toCheckAgainst, "toCheckAgainst");
		this.words = words;
		this.currentIndex = 0;
		this.toCheckAgainst = toCheckAgainst;
	}


	/**
	 * Gets the current attempt.
	 *
	 * @return the current attempt
	 */
	public String getCurrentAttempt()
	{
		if (currentIndex < words.size())
		{
			final String currentAttempt = words.get(currentIndex);
			return currentAttempt;
		}
		return null;
	}

	/**
	 * Increments the word list current index.
	 *
	 * @return true, if the current index was incremented otherwise false.
	 */
	public boolean increment()
	{
		if (currentIndex == words.size())
		{
			return false;
		}
		currentIndex++;
		return true;
	}

	public boolean process()
	{
		boolean continueIterate = true;
		boolean found = false;
		String attempt = getCurrentAttempt();
		while (continueIterate)
		{
			if (attempt.equals(toCheckAgainst))
			{
				System.out.println("Password Found: " + attempt);
				found = true;
				break;
			}
			attempt = getCurrentAttempt();
			System.out.println("Tried: " + attempt);
			continueIterate = increment();
		}
		return found;
	}
}
