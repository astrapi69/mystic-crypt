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
package io.github.astrapi69.mystic.crypt.processor.wordlist;

import java.util.List;

import io.github.astrapi69.check.Check;

/**
 * The class {@link WordlistsProcessor} can process a list of words. For an example see the unit
 * test.
 */
public class WordlistsProcessor
{

	/** The word list. */
	private final List<String> words;
	/** The current index. */
	private int currentIndex;
	/** The password to check against it. */
	private String toCheckAgainst;

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
	 * Gets to check against.
	 *
	 * @return the to check against
	 */
	public String getToCheckAgainst()
	{
		return this.toCheckAgainst;
	}

	/**
	 * Sets to check against.
	 *
	 * @param toCheckAgainst
	 *            the to check against
	 */
	public void setToCheckAgainst(String toCheckAgainst)
	{
		this.toCheckAgainst = toCheckAgainst;
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
				found = true;
				break;
			}
			attempt = getCurrentAttempt();
			continueIterate = increment();
		}
		return found;
	}
}
