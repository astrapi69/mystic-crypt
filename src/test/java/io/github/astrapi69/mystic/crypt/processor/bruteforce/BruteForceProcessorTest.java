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
package io.github.astrapi69.mystic.crypt.processor.bruteforce;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The unit test class for the class {@link BruteForceProcessor}
 */
public class BruteForceProcessorTest
{

	/** A tiny alphabet keeps every brute force run in this class in the microsecond range */
	private static final char[] ALPHABET_AB = { 'a', 'b' };

	private static final char[] ALPHABET_ABC = { 'a', 'b', 'c' };

	/**
	 * A scenario that describes the expected sequence of attempts
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param possibleCharacters
	 *            the alphabet to iterate
	 * @param attemptLength
	 *            the initial length of an attempt
	 * @param expectedAttempts
	 *            the expected attempts in the expected order
	 */
	record AttemptSequenceCase(String description, char[] possibleCharacters, int attemptLength,
		List<String> expectedAttempts) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	/**
	 * A scenario for a brute force search of a concrete target
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param possibleCharacters
	 *            the alphabet to iterate
	 * @param attemptLength
	 *            the initial length of an attempt
	 * @param target
	 *            the searched target
	 * @param expectedAttemptCount
	 *            the expected number of attempts until the target is found
	 */
	record SearchCase(String description, char[] possibleCharacters, int attemptLength,
		String target, int expectedAttemptCount) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static Stream<AttemptSequenceCase> attemptSequenceCases()
	{
		return Stream.of(
			new AttemptSequenceCase("two characters, length one, overflows to length two",
				ALPHABET_AB, 1, List.of("a", "b", "aa", "ab", "ba", "bb", "aaa")),
			new AttemptSequenceCase("three characters, length one", ALPHABET_ABC, 1,
				List.of("a", "b", "c", "aa", "ab", "ac", "ba")),
			new AttemptSequenceCase("two characters, length two", ALPHABET_AB, 2,
				List.of("aa", "ab", "ba", "bb", "aaa", "aab")));
	}

	/**
	 * Test method for {@link BruteForceProcessor#increment()} and
	 * {@link BruteForceProcessor#getCurrentAttempt()}, the processor has to iterate the alphabet
	 * from the right to the left and has to grow the attempt as soon as every combination of the
	 * current length is used
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("attemptSequenceCases")
	public void increment_iteratesEveryCombinationAndGrowsTheAttempt(
		final AttemptSequenceCase testCase)
	{
		BruteForceProcessor processor = new BruteForceProcessor(testCase.possibleCharacters(),
			testCase.attemptLength());

		List<String> attempts = new ArrayList<>();
		for (int i = 0; i < testCase.expectedAttempts().size(); i++)
		{
			attempts.add(processor.getCurrentAttempt());
			processor.increment();
		}

		assertEquals(testCase.expectedAttempts(), attempts);
	}

	/**
	 * Test method for {@link BruteForceProcessor#getCurrentAttempt()}, the first attempt consists
	 * only of the first character of the alphabet
	 */
	@Test
	public void increment_withAnEmptyAttempt_isANoOp()
	{
		BruteForceProcessor processor = new BruteForceProcessor(ALPHABET_ABC, 0);

		assertEquals("", processor.getCurrentAttempt());
		processor.increment();
		assertEquals("", processor.getCurrentAttempt());
	}

	/**
	 * Test method for {@link BruteForceProcessor#getCurrentAttempt()}
	 */
	@Test
	public void getCurrentAttempt_startsWithTheFirstCharacterOfTheAlphabet()
	{
		assertEquals("a", new BruteForceProcessor(ALPHABET_ABC, 1).getCurrentAttempt());
		assertEquals("aaa", new BruteForceProcessor(ALPHABET_ABC, 3).getCurrentAttempt());
	}

	static Stream<SearchCase> searchCases()
	{
		return Stream.of(new SearchCase("first attempt already matches", ALPHABET_AB, 1, "a", 1),
			new SearchCase("last character of the alphabet", ALPHABET_ABC, 1, "c", 3),
			new SearchCase("target longer than the initial attempt", ALPHABET_AB, 1, "ba", 5),
			new SearchCase("target of the initial length", ALPHABET_ABC, 2, "bc", 6));
	}

	/**
	 * Test method for {@link BruteForceProcessor}, a brute force search over a tiny alphabet finds
	 * every target and needs exactly as many attempts as the target has predecessors
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("searchCases")
	public void bruteForceSearch_findsTheTargetAfterTheExpectedNumberOfAttempts(
		final SearchCase testCase)
	{
		BruteForceProcessor processor = new BruteForceProcessor(testCase.possibleCharacters(),
			testCase.attemptLength());

		int attemptCount = 0;
		boolean found = false;
		// the guard only protects the test from an endless loop, every case below is found long
		// before the guard is reached
		while (attemptCount < 1000)
		{
			attemptCount++;
			if (testCase.target().equals(processor.getCurrentAttempt()))
			{
				found = true;
				break;
			}
			processor.increment();
		}

		assertTrue(found);
		assertEquals(testCase.expectedAttemptCount(), attemptCount);
	}

	/**
	 * Test method for {@link BruteForceProcessor}, every attempt of a given length is generated
	 * exactly once before the attempt grows
	 */
	@Test
	public void increment_generatesEveryCombinationOfALengthExactlyOnce()
	{
		BruteForceProcessor processor = new BruteForceProcessor(ALPHABET_ABC, 2);

		List<String> attempts = new ArrayList<>();
		for (int i = 0; i < 9; i++)
		{
			attempts.add(processor.getCurrentAttempt());
			processor.increment();
		}

		assertEquals(9, attempts.stream().distinct().count());
		assertTrue(attempts.stream().allMatch(attempt -> attempt.length() == 2));
		// the next attempt after the last combination of the length two is the first combination of
		// the length three
		assertEquals("aaa", processor.getCurrentAttempt());
	}
}
