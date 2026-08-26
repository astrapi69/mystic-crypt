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
package io.github.astrapi69.mystic.crypt.cli;

import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import io.github.astrapi69.crypt.api.obfuscation.rule.Operation;
import io.github.astrapi69.crypt.data.obfuscation.rule.ObfuscationOperationRule;

/**
 * Parses the {@code --rule} values of {@code obfuscate} and {@code disentangle}, which come in two
 * shapes.
 * <p>
 * The plain shape is a substitution: {@code a=x} replaces every {@code a} with an {@code x}. The
 * operated shape adds an operation and the positions it applies at: {@code a=x:UPPERCASE@0,3} still
 * replaces {@code a} with {@code x} everywhere except at index 0 and index 3, where it writes the
 * operated character - an uppercase {@code A} - instead.
 * <p>
 * A rule set is either all plain or contains at least one operated rule; the second case takes the
 * whole set through the operated obfuscator, so the two shapes can be mixed in one run.
 */
final class ObfuscationRuleSupport
{

	/** Separates the replacement from the operation. */
	private static final String OPERATION_SEPARATOR = ":";

	/** Separates the operation from the indexes it applies at. */
	private static final String INDEX_SEPARATOR = "@";

	private ObfuscationRuleSupport()
	{
	}

	/**
	 * One parsed rule set.
	 *
	 * @param simple
	 *            the plain substitutions, when no rule carries an operation
	 * @param operated
	 *            the operated rules, when at least one does
	 */
	record Rules(BiMap<Character, Character> simple,
		BiMap<Character, ObfuscationOperationRule<Character, Character>> operated) {

		/**
		 * Whether this rule set has to go through the operated obfuscator.
		 *
		 * @return true if any rule carries an operation
		 */
		boolean isOperated()
		{
			return operated != null;
		}
	}

	/**
	 * Parses the rule values as picocli collected them.
	 *
	 * @param rules
	 *            the character to rule-text map
	 * @return the parsed rules
	 * @throws IllegalArgumentException
	 *             if a rule is malformed
	 */
	static Rules parse(final Map<Character, String> rules)
	{
		boolean anyOperated = false;
		for (final String value : rules.values())
		{
			anyOperated = anyOperated || value.contains(OPERATION_SEPARATOR);
		}
		if (!anyOperated)
		{
			final BiMap<Character, Character> simple = HashBiMap.create();
			for (final Map.Entry<Character, String> entry : rules.entrySet())
			{
				simple.put(entry.getKey(), replacementOf(entry.getValue()));
			}
			return new Rules(simple, null);
		}
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> operated = HashBiMap
			.create();
		for (final Map.Entry<Character, String> entry : rules.entrySet())
		{
			operated.put(entry.getKey(), operatedRuleOf(entry.getKey(), entry.getValue()));
		}
		return new Rules(null, operated);
	}

	/**
	 * Reverses what
	 * {@link io.github.astrapi69.mystic.crypt.obfuscation.character.ObfuscatorExtensions#obfuscateWith}
	 * produced.
	 * <p>
	 * The library's own operated {@code disentangle} does not do this correctly: for the rules
	 * {@code a=x:UPPERCASE@0} and {@code b=y} it turns {@code Ayx} back into {@code ayx} rather
	 * than into {@code aba}, and {@code disentangleImproved} throws a NullPointerException on the
	 * same input. Reversing this rule shape is completely determined - at a named position the
	 * operated character stands for the original, everywhere else the replacement does - so it is
	 * done here rather than on top of a reversal that does not reverse.
	 *
	 * @param rules
	 *            the same rules the text was obfuscated with
	 * @param obfuscated
	 *            the obfuscated text
	 * @return the original text
	 */
	static String disentangleOperated(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules,
		final String obfuscated)
	{
		final StringBuilder text = new StringBuilder(obfuscated.length());
		for (int position = 0; position < obfuscated.length(); position++)
		{
			text.append(originalOf(rules, obfuscated.charAt(position), position));
		}
		return text.toString();
	}

	private static char originalOf(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules,
		final char obfuscated, final int position)
	{
		for (final ObfuscationOperationRule<Character, Character> rule : rules.values())
		{
			// a position the rule operates at carries the operated character, not the replacement
			if (rule.getIndexes().contains(position)
				&& Operation.operate(rule.getCharacter(), rule.getOperation()) == obfuscated)
			{
				return rule.getCharacter();
			}
		}
		for (final ObfuscationOperationRule<Character, Character> rule : rules.values())
		{
			if (rule.getReplaceWith() == obfuscated)
			{
				return rule.getCharacter();
			}
		}
		// a character no rule produced was never obfuscated, so it stands for itself
		return obfuscated;
	}

	private static Character replacementOf(final String value)
	{
		if (value.length() != 1)
		{
			throw new IllegalArgumentException("a substitution replaces one character with one "
				+ "character, as in a=x, but the replacement was '" + value + "'");
		}
		return value.charAt(0);
	}

	private static ObfuscationOperationRule<Character, Character> operatedRuleOf(
		final Character character, final String value)
	{
		final int operationAt = value.indexOf(OPERATION_SEPARATOR);
		if (operationAt < 0)
		{
			// a plain rule standing next to operated ones: it substitutes everywhere and operates
			// nowhere, which is what an empty index set says
			return ObfuscationOperationRule.<Character, Character> builder().character(character)
				.replaceWith(replacementOf(value)).operation(Operation.NONE)
				.indexes(new HashSet<>()).build();
		}
		final Character replaceWith = replacementOf(value.substring(0, operationAt));
		final String rest = value.substring(operationAt + 1);
		final int indexAt = rest.indexOf(INDEX_SEPARATOR);
		final String operationName = indexAt < 0 ? rest : rest.substring(0, indexAt);
		final Set<Integer> indexes = indexAt < 0
			? new HashSet<>()
			: parseIndexes(rest.substring(indexAt + 1));
		return ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(parseOperation(operationName)).indexes(indexes)
			.build();
	}

	private static Operation parseOperation(final String name)
	{
		try
		{
			return Operation.valueOf(name.trim().toUpperCase(Locale.ROOT));
		}
		catch (final IllegalArgumentException unknown)
		{
			throw new IllegalArgumentException("'" + name + "' is not an operation. Use UPPERCASE, "
				+ "LOWERCASE, NEGATE or NONE.", unknown);
		}
	}

	private static Set<Integer> parseIndexes(final String text)
	{
		final Set<Integer> indexes = new TreeSet<>();
		for (final String part : text.split(","))
		{
			indexes.add(parseIndex(part.trim()));
		}
		return indexes;
	}

	private static Integer parseIndex(final String part)
	{
		try
		{
			final int index = Integer.parseInt(part);
			if (index < 0)
			{
				throw new IllegalArgumentException(
					"a position cannot be negative, but was " + index);
			}
			return index;
		}
		catch (final NumberFormatException notANumber)
		{
			throw new IllegalArgumentException("the positions after '" + INDEX_SEPARATOR
				+ "' are numbers separated by commas, but one was '" + part + "'", notANumber);
		}
	}
}
