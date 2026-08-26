/*
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
package io.github.astrapi69.mystic.crypt.obfuscation.character;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import io.github.astrapi69.crypt.api.obfuscation.rule.Operation;
import io.github.astrapi69.crypt.data.obfuscation.rule.ObfuscationOperationRule;

/**
 * Regression tests for issue #95: {@link ObfuscatorExtensions#disentangle} did not reverse what
 * {@link ObfuscatorExtensions#obfuscateWith} produced.
 * <p>
 * The property under test is the only one that matters for a reversible obfuscation: whatever went
 * in comes back out, for any text and any rule set.
 */
class ObfuscatorExtensionsRoundTripTest
{

	/**
	 * Builds one rule.
	 *
	 * @param character
	 *            the character the rule is for
	 * @param replaceWith
	 *            what replaces it
	 * @param operation
	 *            the operation, or null for a plain substitution
	 * @param indexes
	 *            the positions the operation applies at
	 * @return the rule
	 */
	private static ObfuscationOperationRule<Character, Character> rule(char character,
		char replaceWith, Operation operation, Integer... indexes)
	{
		Set<Integer> positions = new HashSet<>();
		for (Integer index : indexes)
		{
			positions.add(index);
		}
		return ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation == null ? Operation.NONE : operation)
			.indexes(positions).build();
	}

	private static BiMap<Character, ObfuscationOperationRule<Character, Character>> newRules()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = HashBiMap.create();
		rules.put('a', rule('a', 'x', Operation.UPPERCASE, 0));
		rules.put('b', rule('b', 'y', null));
		return rules;
	}

	/** The exact case from the issue: an operated rule next to a plain one. */
	@Test
	void theCaseFromTheIssueComesBackUnchanged()
	{
		String obfuscated = ObfuscatorExtensions.obfuscateWith(newRules(), "aba");

		assertEquals("Ayx", obfuscated, "the obfuscation itself was never in question");
		assertEquals("aba", ObfuscatorExtensions.disentangle(newRules(), obfuscated),
			"the reversal must give back what went in");
	}

	@ParameterizedTest
	@ValueSource(strings = { "aba", "banana", "aaa", "abab", "b", "a", "", "no rules here" })
	void everyTextSurvivesTheRoundTrip(String text)
	{
		String obfuscated = ObfuscatorExtensions.obfuscateWith(newRules(), text);

		assertEquals(text, ObfuscatorExtensions.disentangle(newRules(), obfuscated),
			"'" + text + "' became '" + obfuscated + "'");
	}

	/**
	 * A character that no rule produced but that is itself a rule key must not disappear. The old
	 * code appended an unmatched character only when it was not a key, which dropped it silently.
	 */
	@Test
	void aCharacterThatIsARuleKeyButWasNeverProducedIsNotDropped()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = HashBiMap.create();
		// 'a' is replaced by 'z', so a literal 'a' in the obfuscated text was never produced by
		// this rule set and stands for itself
		rules.put('a', rule('a', 'z', null));

		assertEquals("qaq", ObfuscatorExtensions.disentangle(rules, "qaq"),
			"a character no rule produced stands for itself, even when it is a rule key");
	}

	/**
	 * Two rules must not both append for the same character. The old code continued through the
	 * remaining rules after a match instead of stopping.
	 */
	@Test
	void aCharacterIsReversedOnceEvenWhenSeveralRulesCouldLookAtIt()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = HashBiMap.create();
		rules.put('a', rule('a', 'x', null));
		rules.put('b', rule('b', 'y', null));
		rules.put('c', rule('c', 'z', null));

		assertEquals("abc", ObfuscatorExtensions.disentangle(rules, "xyz"),
			"three characters in must be three characters out");
	}

	/**
	 * The limitation this pins, so it is not mistaken for a defect: the scheme is only reversible
	 * while the text contains none of the replacement characters. With {@code a -> x}, a literal
	 * {@code x} in the text is indistinguishable from an obfuscated {@code a}, and comes back as an
	 * {@code a}. That is inherent to a character substitution, not something the reversal can
	 * repair, which is what {@link ObfuscatorExtensions#validate} exists to warn about for the
	 * related case of a replacement that is itself a rule key.
	 */
	@Test
	void aTextThatAlreadyContainsAReplacementCharacterCannotComeBackUnchanged()
	{
		String text = "mixed ab and text";

		String obfuscated = ObfuscatorExtensions.obfuscateWith(newRules(), text);

		assertEquals("mixed xy xnd text", obfuscated);
		assertEquals("miaed ab and teat", ObfuscatorExtensions.disentangle(newRules(), obfuscated),
			"the literal x characters of 'mixed' and 'text' come back as a, because nothing "
				+ "distinguishes them from an obfuscated a");
	}

	@Test
	void theRulesAreNotLeftCarryingStateFromTheTextTheyRead()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = newRules();

		String first = ObfuscatorExtensions.disentangle(rules,
			ObfuscatorExtensions.obfuscateWith(rules, "aba"));
		String second = ObfuscatorExtensions.disentangle(rules,
			ObfuscatorExtensions.obfuscateWith(rules, "aba"));

		assertEquals(first, second,
			"reusing the same rule objects must give the same answer twice");
		assertEquals("aba", second);
	}
}
