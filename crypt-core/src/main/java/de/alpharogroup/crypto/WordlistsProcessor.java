package de.alpharogroup.crypto;

import java.util.List;

import lombok.Getter;
import lombok.Setter;
import de.alpharogroup.check.Check;

public class WordlistsProcessor
{
	private List<String> words;
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
