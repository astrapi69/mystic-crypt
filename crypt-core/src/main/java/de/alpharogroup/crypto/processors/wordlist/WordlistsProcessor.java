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
package de.alpharogroup.crypto.processors.wordlist;

import java.util.List;

import org.apache.log4j.Logger;

import de.alpharogroup.check.Check;
import lombok.Getter;
import lombok.Setter;

/**
 * The class {@link WordlistsProcessor} can process a list of words. For an example see the unit
 * test.
 */
public class WordlistsProcessor
{

	/** The Constant logger. */
	private static final Logger logger = Logger.getLogger(WordlistsProcessor.class.getName());

	/** The current index. */
	private int currentIndex;

	/** The password to check against it. */
	@Getter
	@Setter
	private String toCheckAgainst;

	/** The word list. */
	private final List<String> words;

	/**
	 * Instantiates a new {@link WordlistsProcessor} object.
	 *
	 * @param words
	 *            the word list
	 */
	public WordlistsProcessor(final List<String> words)
	{
		this.words = words;
		this.currentIndex = 0;
	}

	/**
	 * Instantiates a new wordlists processor.
	 *
	 * @param words
	 *            the words
	 * @param toCheckAgainst
	 *            the to check against
	 */
	public WordlistsProcessor(final List<String> words, final String toCheckAgainst)
	{
		Check.get().notNull(toCheckAgainst, "toCheckAgainst").notEmpty(toCheckAgainst,
			"toCheckAgainst");
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

	/**
	 * Processes the word list.
	 *
	 * @return true, if successful
	 */
	public boolean process()
	{
		boolean continueIterate = true;
		boolean found = false;
		String attempt = getCurrentAttempt();
		while (continueIterate)
		{
			if (attempt.equals(toCheckAgainst))
			{
				logger.debug("Password Found: " + attempt);
				found = true;
				break;
			}
			attempt = getCurrentAttempt();
			logger.debug("Tried: " + attempt);
			continueIterate = increment();
		}
		return found;
	}
}
