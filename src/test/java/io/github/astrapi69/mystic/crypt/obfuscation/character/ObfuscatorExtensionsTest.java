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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.google.common.collect.BiMap;
import com.google.common.collect.ForwardingMap;
import com.google.common.collect.HashBiMap;

import io.github.astrapi69.collection.list.ListFactory;
import io.github.astrapi69.collection.pair.KeyValuePair;
import io.github.astrapi69.collection.set.SetFactory;
import io.github.astrapi69.crypt.api.obfuscation.rule.Operation;
import io.github.astrapi69.crypt.data.obfuscation.rule.ObfuscationOperationRule;

/**
 * The unit test class for the class {@link ObfuscatorExtensions}
 */
public class ObfuscatorExtensionsTest
{

	/**
	 * A single obfuscate/disentangle round trip scenario
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param input
	 *            the input to obfuscate
	 * @param expectedObfuscated
	 *            the expected obfuscated result
	 */
	record RoundTripCase(String description, String input, String expectedObfuscated) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	/**
	 * A scenario for the validation methods
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param rules
	 *            the rules to validate
	 * @param input
	 *            the input to check
	 * @param expected
	 *            the expected result
	 */
	record ValidationCase(String description,
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules, String input,
		boolean expected) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	/**
	 * A scenario for a method that rejects a null argument
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param executable
	 *            the call that must be rejected
	 */
	record NullArgumentCase(String description, Executable executable) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static ObfuscationOperationRule<Character, Character> newRule(final char character,
		final char replaceWith, final Operation operation, final Integer... indexes)
	{
		return ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(SetFactory.newHashSet(indexes))
			.build();
	}

	/**
	 * Three chained rules a-&gt;b, b-&gt;c, c-&gt;d, every replacement character except the last
	 * one is itself an obfuscated character, which is what makes the map disentanglable
	 *
	 * @return the newly created rules
	 */
	static BiMap<Character, ObfuscationOperationRule<Character, Character>> newSmallChainRules()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = HashBiMap.create();
		rules.put('a', newRule('a', 'b', Operation.UPPERCASE, 0, 2));
		rules.put('b', newRule('b', 'c', Operation.UPPERCASE, 2));
		rules.put('c', newRule('c', 'd', Operation.UPPERCASE, 3));
		return rules;
	}

	static Stream<RoundTripCase> roundTripCases()
	{
		return Stream.of(new RoundTripCase("single character at an operated index", "a", "A"),
			new RoundTripCase("mixed operated and replaced characters", "abac", "AcAC"),
			new RoundTripCase("operation only on the first index", "hello", "Hfmmp"),
			new RoundTripCase("repeated characters", "food", "Fppe"),
			new RoundTripCase("longer word", "leonardo", "Lfpobsep"));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#obfuscateWith(BiMap, String)} and
	 * {@link ObfuscatorExtensions#disentangle(BiMap, String)}, obfuscating and disentangling again
	 * has to result in the original input
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("roundTripCases")
	public void obfuscateWith_thenDisentangle_recoversTheOriginalInput(final RoundTripCase testCase)
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = ObfuscationOperationTestData
			.getFirstBiMapObfuscationOperationRules();

		String obfuscated = ObfuscatorExtensions.obfuscateWith(rules, testCase.input());
		assertEquals(testCase.expectedObfuscated(), obfuscated);

		String disentangled = ObfuscatorExtensions.disentangle(rules, obfuscated);
		assertEquals(testCase.input(), disentangled);
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#isObfuscableAndDisentanglable(BiMap, String)},
	 * every round trip scenario has to be recognized as disentanglable
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("roundTripCases")
	public void isObfuscableAndDisentanglable_isTrueForEveryRoundTrippingInput(
		final RoundTripCase testCase)
	{
		assertTrue(ObfuscatorExtensions.isObfuscableAndDisentanglable(
			ObfuscationOperationTestData.getFirstBiMapObfuscationOperationRules(),
			testCase.input()));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#obfuscateWithCharArray(BiMap, String)}, the char
	 * array based implementation has to obfuscate exactly like
	 * {@link ObfuscatorExtensions#obfuscateWith(BiMap, String)} for operation based rules
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("roundTripCases")
	public void obfuscateWithCharArray_producesTheSameResultAsObfuscateWith(
		final RoundTripCase testCase)
	{
		String withCharArray = ObfuscatorExtensions.obfuscateWithCharArray(
			ObfuscationOperationTestData.getFirstBiMapObfuscationOperationRules(),
			testCase.input());
		assertEquals(testCase.expectedObfuscated(), withCharArray);
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#obfuscateWith(BiMap, String)}, characters without
	 * a rule have to stay untouched
	 */
	@Test
	public void obfuscateWith_leavesCharactersWithoutARuleUnchanged()
	{
		assertEquals("123 !", ObfuscatorExtensions.obfuscateWith(newSmallChainRules(), "123 !"));
		assertEquals("1b2",
			ObfuscatorExtensions.obfuscateWithCharArray(newSmallChainRules(), "1a2"));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#obfuscateWith(BiMap, String)} and
	 * {@link ObfuscatorExtensions#obfuscateWithCharArray(BiMap, String)}, the operation
	 * {@link Operation#NONE} results in an unchanged character for the first method while the char
	 * array based method falls back to the replacement character
	 */
	@Test
	public void obfuscateWith_withOperationNone_keepsTheCharacterWhileCharArrayReplacesIt()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = HashBiMap.create();
		rules.put('a', newRule('a', 'x', Operation.NONE, 0));

		assertEquals("ab", ObfuscatorExtensions.obfuscateWith(rules, "ab"));

		BiMap<Character, ObfuscationOperationRule<Character, Character>> freshRules = HashBiMap
			.create();
		freshRules.put('a', newRule('a', 'x', Operation.NONE, 0));
		assertEquals("xb", ObfuscatorExtensions.obfuscateWithCharArray(freshRules, "ab"));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#disentangle(BiMap, String)}, a character that was
	 * operated with {@link Operation#NEGATE} on an index of the rule has to be restored
	 */
	@Test
	public void disentangle_restoresACharacterThatWasNegatedAtARuleIndex()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = HashBiMap.create();
		rules.put('a', newRule('a', 'x', Operation.NEGATE, 0));

		assertEquals("Ax", ObfuscatorExtensions.obfuscateWith(rules, "aa"));

		BiMap<Character, ObfuscationOperationRule<Character, Character>> freshRules = HashBiMap
			.create();
		freshRules.put('a', newRule('a', 'x', Operation.NEGATE, 0));
		// the negated character on the index of the rule is restored to its original lower case
		// character
		assertEquals('a', ObfuscatorExtensions.disentangle(freshRules, "Ax").charAt(0));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#disentangle(BiMap, String)}, the replacement
	 * character on an index of the rule has to be restored to the original character
	 */
	@Test
	public void disentangle_restoresTheReplacementCharacterOnARuleIndex()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = HashBiMap.create();
		rules.put('a', newRule('a', 'x', Operation.UPPERCASE, 0));

		assertEquals("a", ObfuscatorExtensions.disentangle(rules, "x"));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#disentangle(List, String)}, the list based
	 * variant resolves every operated and every replacement character back to its origin
	 */
	@Test
	public void disentangle_withListOfRules_recoversTheObfuscatedText()
	{
		List<KeyValuePair<Character, ObfuscationOperationRule<Character, Character>>> rules = ListFactory
			.newArrayList();
		newSmallChainRules().forEach((key, value) -> rules
			.add(KeyValuePair.<Character, ObfuscationOperationRule<Character, Character>> builder()
				.key(key).value(value).build()));

		assertEquals("abac", ObfuscatorExtensions.disentangle(rules, "AcAC"));
		// characters that are neither an operated nor a replacement character stay unchanged
		assertEquals("zzz", ObfuscatorExtensions.disentangle(rules, "zzz"));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#swapMapWithReplaceWithAsKey(BiMap)}, the swapped
	 * map has to contain the operated character and the replacement character as keys
	 */
	@Test
	public void swapMapWithReplaceWithAsKey_mapsOperatedAndReplacementCharacterToTheOrigin()
	{
		Map<Character, Character> swapped = ObfuscatorExtensions
			.swapMapWithReplaceWithAsKey(newSmallChainRules());

		assertEquals(6, swapped.size());
		assertEquals('a', swapped.get('A'));
		assertEquals('a', swapped.get('b'));
		assertEquals('b', swapped.get('B'));
		assertEquals('b', swapped.get('c'));
		assertEquals('c', swapped.get('C'));
		assertEquals('c', swapped.get('d'));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#swapMapWithReplaceWithAsKey(BiMap)}, a rule
	 * without an operation contributes only its replacement character
	 */
	@Test
	public void swapMapWithReplaceWithAsKey_withoutOperation_mapsOnlyTheReplacementCharacter()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = HashBiMap.create();
		rules.put('a', newRule('a', 'x', Operation.NONE, 0));

		Map<Character, Character> swapped = ObfuscatorExtensions.swapMapWithReplaceWithAsKey(rules);

		assertEquals(1, swapped.size());
		assertEquals('a', swapped.get('x'));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#swapOperatedMapWithReplaceWithAsKey(BiMap)}, the
	 * swapped map has to resolve the operated and the replacement character to the whole rule
	 */
	@Test
	public void swapOperatedMapWithReplaceWithAsKey_mapsOperatedAndReplacementCharacterToTheRule()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = newSmallChainRules();
		ObfuscationOperationRule<Character, Character> ruleOfA = rules.get('a');

		Map<Character, ObfuscationOperationRule<Character, Character>> swapped = ObfuscatorExtensions
			.swapOperatedMapWithReplaceWithAsKey(rules);

		assertEquals(6, swapped.size());
		assertEquals(ruleOfA, swapped.get('A'));
		assertEquals(ruleOfA, swapped.get('b'));
		assertEquals('A', swapped.get('A').getOperatedCharacter().get());
		// 'c' is the replacement character of the rule for 'b'
		assertEquals('b', swapped.get('c').getCharacter());
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#swapOperatedMapWithReplaceWithAsKey(BiMap)}, a
	 * rule without indexes contributes only its replacement character
	 */
	@Test
	public void swapOperatedMapWithReplaceWithAsKey_withoutIndexes_mapsOnlyTheReplacementCharacter()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = HashBiMap.create();
		rules.put('a', newRule('a', 'x', Operation.UPPERCASE));

		Map<Character, ObfuscationOperationRule<Character, Character>> swapped = ObfuscatorExtensions
			.swapOperatedMapWithReplaceWithAsKey(rules);

		assertEquals(1, swapped.size());
		assertEquals('a', swapped.get('x').getCharacter());
	}

	static Stream<ValidationCase> validationCases()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> operatedCharacterIsAKey = HashBiMap
			.create();
		operatedCharacterIsAKey.put('a', newRule('a', 'x', Operation.UPPERCASE, 0));
		operatedCharacterIsAKey.put('A', newRule('A', 'y', Operation.LOWERCASE, 0));

		BiMap<Character, ObfuscationOperationRule<Character, Character>> withoutOperation = HashBiMap
			.create();
		withoutOperation.put('a', newRule('a', 'x', Operation.NONE, 0));

		return Stream.of(
			new ValidationCase("chained rules are disentanglable", newSmallChainRules(), "abac",
				true),
			new ValidationCase("operated character is itself an obfuscated character",
				operatedCharacterIsAKey, "abac", false),
			new ValidationCase("without an operation the character stays a key of the rules",
				withoutOperation, "abac", false));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#validate(BiMap)}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("validationCases")
	public void validate_detectsRulesThatCanNotBeDisentangled(final ValidationCase testCase)
	{
		assertEquals(testCase.expected(), ObfuscatorExtensions.validate(testCase.rules()));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#isObfuscableAndDisentanglable(BiMap, String)},
	 * invalid rules can never be disentangled
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("validationCases")
	public void isObfuscableAndDisentanglable_followsTheValidationResult(
		final ValidationCase testCase)
	{
		assertEquals(testCase.expected(),
			ObfuscatorExtensions.isObfuscableAndDisentanglable(testCase.rules(), testCase.input()));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#isObfuscableAndDisentanglable(BiMap, String)},
	 * valid rules that do not round trip the given input have to be rejected as well.
	 * <p>
	 * "ca" used to be such an input and no longer is: it round trips since issue #95, and the
	 * helper says so. What still does not round trip is a text holding a character that the rules
	 * produce as a replacement without ever taking it as an input - a literal {@code d} is
	 * indistinguishable from an obfuscated {@code c} and comes back as one.
	 */
	@Test
	public void isObfuscableAndDisentanglable_isFalseWhenTheInputDoesNotRoundTrip()
	{
		assertTrue(ObfuscatorExtensions.validate(newSmallChainRules()));
		assertTrue(ObfuscatorExtensions.isObfuscableAndDisentanglable(newSmallChainRules(), "ca"));
		assertFalse(ObfuscatorExtensions.isObfuscableAndDisentanglable(newSmallChainRules(), "d"));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#inverse(ObfuscationOperationRule)}, the character
	 * and the replacement character have to be swapped and the inverted flag has to be toggled
	 */
	@Test
	public void inverse_rule_swapsCharacterWithReplaceWithAndTogglesTheInvertedFlag()
	{
		ObfuscationOperationRule<Character, Character> rule = newRule('a', 'x', Operation.UPPERCASE,
			0);
		assertFalse(rule.isInverted());

		ObfuscatorExtensions.inverse(rule);

		assertEquals('x', rule.getCharacter());
		assertEquals('a', rule.getReplaceWith());
		assertTrue(rule.isInverted());

		ObfuscatorExtensions.inverse(rule);

		assertEquals('a', rule.getCharacter());
		assertEquals('x', rule.getReplaceWith());
		assertFalse(rule.isInverted());
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#tryToClone(Object)}, a clonable object has to be
	 * returned as an equal but distinct instance
	 */
	@Test
	public void tryToClone_returnsAnEqualButDistinctCopy()
	{
		ObfuscationOperationRule<Character, Character> rule = newRule('a', 'x', Operation.UPPERCASE,
			0);

		Optional<ObfuscationOperationRule<Character, Character>> cloned = ObfuscatorExtensions
			.tryToClone(rule);

		assertTrue(cloned.isPresent());
		assertEquals(rule, cloned.get());
		assertNotSame(rule, cloned.get());
	}

	/**
	 * A {@link BiMap} that can be cloned by {@code CloneObjectExtensions}: it implements
	 * {@link Cloneable} and declares its own {@link #clone()} that deep copies every rule
	 */
	static final class CloneableBiMap
		extends
			ForwardingMap<Character, ObfuscationOperationRule<Character, Character>>
		implements
			BiMap<Character, ObfuscationOperationRule<Character, Character>>,
			Cloneable
	{
		private final BiMap<Character, ObfuscationOperationRule<Character, Character>> delegate;

		@Override
		public ObfuscationOperationRule<Character, Character> forcePut(final Character key,
			final ObfuscationOperationRule<Character, Character> value)
		{
			return delegate.forcePut(key, value);
		}

		@Override
		public BiMap<ObfuscationOperationRule<Character, Character>, Character> inverse()
		{
			return delegate.inverse();
		}

		@Override
		public Set<ObfuscationOperationRule<Character, Character>> values()
		{
			return delegate.values();
		}

		CloneableBiMap(
			final BiMap<Character, ObfuscationOperationRule<Character, Character>> delegate)
		{
			this.delegate = delegate;
		}

		@Override
		protected BiMap<Character, ObfuscationOperationRule<Character, Character>> delegate()
		{
			return delegate;
		}

		@Override
		public CloneableBiMap clone()
		{
			BiMap<Character, ObfuscationOperationRule<Character, Character>> copy = HashBiMap
				.create();
			delegate.forEach((character, rule) -> copy.put(character,
				ObfuscationOperationRule.<Character, Character> builder()
					.character(rule.getCharacter()).replaceWith(rule.getReplaceWith())
					.operation(rule.getOperation())
					.indexes(SetFactory.newHashSet(rule.getIndexes())).inverted(rule.isInverted())
					.build()));
			return new CloneableBiMap(copy);
		}
	}

	/**
	 * A {@link BiMap} that claims to be {@link Cloneable} but does not declare a {@code clone()}
	 * method, so {@code CloneObjectExtensions} fails with a {@link NoSuchMethodException}
	 */
	static final class NotReallyCloneableBiMap
		extends
			ForwardingMap<Character, ObfuscationOperationRule<Character, Character>>
		implements
			BiMap<Character, ObfuscationOperationRule<Character, Character>>,
			Cloneable
	{
		private final BiMap<Character, ObfuscationOperationRule<Character, Character>> delegate;

		@Override
		public ObfuscationOperationRule<Character, Character> forcePut(final Character key,
			final ObfuscationOperationRule<Character, Character> value)
		{
			return delegate.forcePut(key, value);
		}

		@Override
		public BiMap<ObfuscationOperationRule<Character, Character>, Character> inverse()
		{
			return delegate.inverse();
		}

		@Override
		public Set<ObfuscationOperationRule<Character, Character>> values()
		{
			return delegate.values();
		}

		NotReallyCloneableBiMap(
			final BiMap<Character, ObfuscationOperationRule<Character, Character>> delegate)
		{
			this.delegate = delegate;
		}

		@Override
		protected BiMap<Character, ObfuscationOperationRule<Character, Character>> delegate()
		{
			return delegate;
		}
	}

	/**
	 * Two independent rules (no replacement character is itself a rule key), which is the
	 * precondition for {@link ObfuscatorExtensions#inverse(BiMap)} to succeed
	 *
	 * @return the newly created rules
	 */
	static BiMap<Character, ObfuscationOperationRule<Character, Character>> newIndependentRules()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = HashBiMap.create();
		rules.put('a', newRule('a', 'x', Operation.UPPERCASE, 0));
		rules.put('b', newRule('b', 'y', Operation.NEGATE, 1));
		rules.put('c', newRule('c', 'z', Operation.NEGATE, 2));
		return rules;
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#inverse(BiMap)} and
	 * {@link ObfuscatorExtensions#disentangleImproved(BiMap, String)} with a plain
	 * {@link HashBiMap}
	 * <p>
	 * Note: this test documents a known defect that is out of scope here. Both methods clone the
	 * whole {@link BiMap} argument over {@link ObfuscatorExtensions#tryToClone(Object)} which wraps
	 * the result of the clone helper in {@link Optional#of(Object)}. The clone helper answers null
	 * for a {@link HashBiMap}, so the methods fail with a {@link NullPointerException} for a plain
	 * {@link HashBiMap}. ({@link ObfuscatorExtensions#inverseToMap(BiMap)} used to be listed here
	 * too, but its own defect - cloning the immutable {@link Character} key - has been fixed, see
	 * {@link #inverseToMap_withACloneableBiMap_mapsEveryRuleToItsCharacter()}.)
	 */
	@Test
	public void inverseAndDisentangleImproved_currentlyFailForPlainHashBiMaps()
	{
		assertThrows(NullPointerException.class,
			() -> ObfuscatorExtensions.inverse(newSmallChainRules()));
		assertThrows(NullPointerException.class,
			() -> ObfuscatorExtensions.disentangleImproved(newSmallChainRules(), "AcAC"));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#inverseToMap(BiMap)}, every rule of the given
	 * {@link BiMap} has to end up as a key of the answered map, mapped to the character it belongs
	 * to. This used to throw a {@link NullPointerException} because the method cloned the immutable
	 * {@link Character} key, whose clone answers null; the key is now used directly.
	 */
	@Test
	public void inverseToMap_withACloneableBiMap_mapsEveryRuleToItsCharacter()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = new CloneableBiMap(
			newIndependentRules());

		Map<ObfuscationOperationRule<Character, Character>, Character> inverted = ObfuscatorExtensions
			.inverseToMap(rules);

		assertEquals(rules.size(), inverted.size());
		assertEquals(Set.of('a', 'b', 'c'), Set.copyOf(inverted.values()));
		inverted.forEach((rule, character) -> assertEquals(rule.getCharacter(), character));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#inverse(BiMap)} with a cloneable {@link BiMap},
	 * the result has to map every inverted rule to its former replacement character and the given
	 * rules must stay untouched
	 */
	@Test
	public void inverse_withACloneableBiMap_invertsEveryRuleOnACopy()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = new CloneableBiMap(
			newIndependentRules());

		BiMap<ObfuscationOperationRule<Character, Character>, Character> inverted = ObfuscatorExtensions
			.inverse(rules);

		assertEquals(rules.size(), inverted.size());
		inverted.forEach((rule, character) -> {
			assertTrue(rule.isInverted());
			assertEquals(rule.getCharacter(), character);
			ObfuscationOperationRule<Character, Character> original = rules
				.get(rule.getReplaceWith());
			assertEquals(original.getReplaceWith(), rule.getCharacter());
			assertFalse(original.isInverted(), "the given rules must not be modified");
		});
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#inverse(BiMap)} with a {@link BiMap} that can not
	 * be cloned, the given rules themselves have to be inverted in place
	 */
	@Test
	public void inverse_withANotCloneableBiMap_invertsTheGivenRulesInPlace()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = new NotReallyCloneableBiMap(
			newIndependentRules());
		ObfuscationOperationRule<Character, Character> ruleOfA = rules.get('a');

		BiMap<ObfuscationOperationRule<Character, Character>, Character> inverted = ObfuscatorExtensions
			.inverse(rules);

		assertTrue(ruleOfA.isInverted());
		assertEquals('x', ruleOfA.getCharacter());
		assertEquals('a', ruleOfA.getReplaceWith());
		assertEquals(Set.of('x', 'y', 'z'), Set.copyOf(inverted.values()));
		assertTrue(inverted.keySet().stream().allMatch(ObfuscationOperationRule::isInverted));
	}

	record ImprovedDisentangleCase(String description, String obfuscated, String expected) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static Stream<ImprovedDisentangleCase> improvedDisentangleCases()
	{
		return Stream.of(
			new ImprovedDisentangleCase("operated characters on their rule index", "ABC", "abc"),
			new ImprovedDisentangleCase("replacement characters", "xyz", "abc"),
			new ImprovedDisentangleCase("mixed with characters without a rule", "AB-xy", "ab-ab"),
			new ImprovedDisentangleCase("an operated character on a foreign index is dropped", "xA",
				"a"));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#disentangleImproved(BiMap, String)} with a
	 * cloneable {@link BiMap}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("improvedDisentangleCases")
	public void disentangleImproved_withACloneableBiMap_restoresTheOriginalCharacters(
		final ImprovedDisentangleCase testCase)
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = new CloneableBiMap(
			newIndependentRules());

		assertEquals(testCase.expected(),
			ObfuscatorExtensions.disentangleImproved(rules, testCase.obfuscated()));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#obfuscateWith(BiMap, String)} and
	 * {@link ObfuscatorExtensions#disentangleImproved(BiMap, String)}, obfuscating and
	 * disentangling again has to result in the original input
	 */
	@Test
	public void obfuscateWith_thenDisentangleImproved_recoversTheOriginalInput()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = new CloneableBiMap(
			newIndependentRules());
		String input = "abcab-cba";

		String obfuscated = ObfuscatorExtensions.obfuscateWith(rules, input);

		assertEquals("ABCxy-zyx", obfuscated);
		assertEquals(input, ObfuscatorExtensions.disentangleImproved(rules, obfuscated));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#tryToClone(Object)}, an object that claims to be
	 * cloneable without a clone method can not be cloned
	 */
	@Test
	public void tryToClone_answersEmptyForAnObjectWithoutACloneMethod()
	{
		assertFalse(ObfuscatorExtensions.tryToClone(new Cloneable()
		{
		}).isPresent());
		assertFalse(ObfuscatorExtensions.tryToClone(new NotReallyCloneableBiMap(HashBiMap.create()))
			.isPresent());
	}

	record CaseOperationCase(String description, char character, Operation operation, String input,
		String expectedObfuscated) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static Stream<CaseOperationCase> caseOperationCases()
	{
		return Stream.of(
			new CaseOperationCase("lowercase operation on an upper case character", 'A',
				Operation.LOWERCASE, "AA", "ax"),
			new CaseOperationCase("uppercase operation on a lower case character", 'a',
				Operation.UPPERCASE, "aa", "Ax"),
			new CaseOperationCase("negate operation on a lower case character", 'a',
				Operation.NEGATE, "aa", "Ax"),
			new CaseOperationCase("negate operation on an upper case character", 'A',
				Operation.NEGATE, "AA", "ax"),
			new CaseOperationCase("uppercase operation on a digit has no case to reverse", '1',
				Operation.UPPERCASE, "11", "1x"),
			new CaseOperationCase("lowercase operation on a digit has no case to reverse", '1',
				Operation.LOWERCASE, "11", "1x"));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#disentangle(BiMap, String)}, the reverse
	 * operation has to respect the case of the obfuscated character
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("caseOperationCases")
	public void disentangle_reversesTheCaseOperationOnTheRuleIndex(final CaseOperationCase testCase)
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = HashBiMap.create();
		rules.put(testCase.character(),
			newRule(testCase.character(), 'x', testCase.operation(), 0));
		rules.put('x', newRule('x', 'y', Operation.UPPERCASE, 5));

		String obfuscated = ObfuscatorExtensions.obfuscateWith(rules, testCase.input());

		assertEquals(testCase.expectedObfuscated(), obfuscated);
		assertEquals(testCase.input(), ObfuscatorExtensions.disentangle(rules, obfuscated));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#obfuscateWith(BiMap, String)} and
	 * {@link ObfuscatorExtensions#disentangle(BiMap, String)} with a rule without indexes, the
	 * operation is never applied and only the replacement is used
	 */
	@Test
	public void obfuscateWith_withARuleWithoutIndexes_neverAppliesTheOperation()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = HashBiMap.create();
		rules.put('h', newRule('h', 'i', Operation.UPPERCASE));
		rules.put('i', newRule('i', 'j', Operation.UPPERCASE, 0));

		assertEquals("ii", ObfuscatorExtensions.obfuscateWith(rules, "hh"));
		assertEquals("ii", ObfuscatorExtensions.obfuscateWithCharArray(rules, "hh"));
		assertEquals("hh", ObfuscatorExtensions.disentangle(rules, "ii"));
		assertEquals(Map.of('i', 'h', 'I', 'i', 'j', 'i'),
			ObfuscatorExtensions.swapMapWithReplaceWithAsKey(rules));
		assertEquals(Set.of('i', 'I', 'j'),
			ObfuscatorExtensions.swapOperatedMapWithReplaceWithAsKey(rules).keySet());
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#swapMapWithReplaceWithAsKey(BiMap)} and
	 * {@link ObfuscatorExtensions#swapOperatedMapWithReplaceWithAsKey(BiMap)} with the
	 * {@link Operation#NONE}, no operated character is added
	 */
	@Test
	public void swapMaps_withTheNoneOperation_mapOnlyTheReplacementCharacter()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = HashBiMap.create();
		rules.put('k', newRule('k', 'l', Operation.NONE, 0, 1));

		assertEquals(Map.of('l', 'k'), ObfuscatorExtensions.swapMapWithReplaceWithAsKey(rules));
		assertEquals(Set.of('l'),
			ObfuscatorExtensions.swapOperatedMapWithReplaceWithAsKey(rules).keySet());
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#disentangle(BiMap, String)}: a character that is
	 * a rule key but can not be the output of the obfuscation stands for itself.
	 * <p>
	 * These rules turn {@code a} into {@code x} or {@code A} and {@code b} into {@code y} or its
	 * negation, so a literal {@code a} or {@code b} in an obfuscated text was never produced by
	 * them. Until issue #95 it was dropped from the output entirely, which is silent data loss
	 * rather than a wrong character.
	 */
	@Test
	public void disentangle_keepsARuleCharacterThatCanNotBeAnObfuscationResult()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = newIndependentRules();

		assertEquals("a-b", ObfuscatorExtensions.disentangle(rules, "a-b"));
		assertEquals("-", ObfuscatorExtensions.disentangle(rules, "-"));
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#obfuscateWith(BiMap, String)},
	 * {@link ObfuscatorExtensions#obfuscateWithCharArray(BiMap, String)} and
	 * {@link ObfuscatorExtensions#disentangle(BiMap, String)} with a rule without an operation, the
	 * character is only replaced and the replacement is resolved on disentangling
	 */
	@Test
	public void obfuscateWith_withARuleWithoutOperation_onlyReplacesTheCharacter()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = HashBiMap.create();
		rules.put('d', newRule('d', 'e', null, 0));
		rules.put('e', newRule('e', 'f', Operation.UPPERCASE, 0));
		rules.put('f', newRule('f', 'g', Operation.UPPERCASE, 9));

		assertEquals("ee", ObfuscatorExtensions.obfuscateWith(rules, "dd"));
		assertEquals("ee", ObfuscatorExtensions.obfuscateWithCharArray(rules, "dd"));
		assertEquals("dd", ObfuscatorExtensions.disentangle(rules, "ee"));
		assertEquals("Ef", ObfuscatorExtensions.obfuscateWith(rules, "ee"));
		assertEquals("ee", ObfuscatorExtensions.disentangle(rules, "Ef"));
		assertEquals(Map.of('e', 'd', 'E', 'e', 'f', 'e', 'F', 'f', 'g', 'f'),
			ObfuscatorExtensions.swapMapWithReplaceWithAsKey(rules));
		assertEquals(Set.of('e', 'E', 'f', 'F', 'g'),
			ObfuscatorExtensions.swapOperatedMapWithReplaceWithAsKey(rules).keySet());
	}

	static Stream<NullArgumentCase> nullArgumentCases()
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = newSmallChainRules();
		return Stream.of(
			new NullArgumentCase("disentangle without rules",
				() -> ObfuscatorExtensions.disentangle(
					(BiMap<Character, ObfuscationOperationRule<Character, Character>>)null,
					"abac")),
			new NullArgumentCase("disentangle without obfuscated text",
				() -> ObfuscatorExtensions.disentangle(rules, null)),
			new NullArgumentCase("inverse without rules",
				() -> ObfuscatorExtensions.inverse(
					(BiMap<Character, ObfuscationOperationRule<Character, Character>>)null)),
			new NullArgumentCase("inverse without rule",
				() -> ObfuscatorExtensions
					.inverse((ObfuscationOperationRule<Character, Character>)null)),
			new NullArgumentCase("inverseToMap without rules",
				() -> ObfuscatorExtensions.inverseToMap(null)),
			new NullArgumentCase("isObfuscableAndDisentanglable without rules",
				() -> ObfuscatorExtensions.isObfuscableAndDisentanglable(null, "abac")),
			new NullArgumentCase("isObfuscableAndDisentanglable without input",
				() -> ObfuscatorExtensions.isObfuscableAndDisentanglable(rules, null)),
			new NullArgumentCase("swapMapWithReplaceWithAsKey without rules",
				() -> ObfuscatorExtensions.swapMapWithReplaceWithAsKey(null)),
			new NullArgumentCase("swapOperatedMapWithReplaceWithAsKey without rules",
				() -> ObfuscatorExtensions.swapOperatedMapWithReplaceWithAsKey(null)),
			new NullArgumentCase("tryToClone without object",
				() -> ObfuscatorExtensions.tryToClone(null)),
			new NullArgumentCase("validate without rules",
				() -> ObfuscatorExtensions.validate(null)));
	}

	/**
	 * Test method that verifies that every method rejects null arguments
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("nullArgumentCases")
	public void everyMethodRejectsNullArguments(final NullArgumentCase testCase)
	{
		assertThrows(NullPointerException.class, testCase.executable());
	}

}
