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
package de.alpharogroup.crypto.obfuscation.character;

import java.util.Map.Entry;
import java.util.Set;

import com.google.common.collect.BiMap;

import de.alpharogroup.crypto.obfuscation.rule.ObfuscationOperationRule;
import de.alpharogroup.crypto.obfuscation.rule.Operation;
import lombok.experimental.UtilityClass;

/**
 * The class {@link ObfuscatorExtensions} provides algorithms for obfuscate strings.
 */
@UtilityClass
public class ObfuscatorExtensions
{

	/**
	 * Obfuscate with the given {@link BiMap}
	 *
	 * @param rules
	 *            the rules
	 * @param toObfuscate
	 *            the {@link String} object to obfuscate
	 * @return the string
	 */
	public static String obfuscateWith(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules,
		final String toObfuscate)
	{
		final StringBuilder sb = new StringBuilder();
		for (int i = 0; i < toObfuscate.length(); i++)
		{
			final char currentCharacter = toObfuscate.charAt(i);
			final Character asCharacter = currentCharacter;
			final String charAsString = Character.toString(currentCharacter);
			if (rules.containsKey(asCharacter))
			{
				final ObfuscationOperationRule<Character, Character> obfuscationOperationRule = rules
					.get(asCharacter);
				final Set<Integer> indexes = obfuscationOperationRule.getIndexes();
				final Operation operation = obfuscationOperationRule.getOperation();
				if (operation != null)
				{
					obfuscationOperationRule
						.setOperatedCharacter(Operation.operate(currentCharacter, operation));
				}
				if (indexes.contains(i))
				{
					if (obfuscationOperationRule.getOperatedCharacter() != null)
					{
						sb.append(obfuscationOperationRule.getOperatedCharacter());
						continue;
					}
				}
				final Character replaceWith = obfuscationOperationRule.getReplaceWith();
				sb.append(replaceWith);

			}
			else
			{
				sb.append(charAsString);
			}
		}
		return sb.toString();
	}

	/**
	 * Disentangle the given obfuscated text with the given {@link BiMap} rules
	 *
	 * @param rules
	 *            the rules
	 * @param obfuscated
	 *            the obfuscated text
	 * @return the string
	 */
	public static String disentangle(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules,
		final String obfuscated)
	{
		boolean processed;
		char currentChar;
		boolean upperCase;
		boolean lowerCase;
		Character currentCharacter;
		final StringBuilder sb = new StringBuilder();
		for (int i = 0; i < obfuscated.length(); i++)
		{
			processed = false;
			currentChar = obfuscated.charAt(i);
			upperCase = Character.isUpperCase(currentChar);
			lowerCase = Character.isLowerCase(currentChar);
			currentCharacter = currentChar;

			for (final Entry<Character, ObfuscationOperationRule<Character, Character>> entry : rules
				.entrySet())
			{
				ObfuscationOperationRule<Character, Character> obfuscationOperationRule = entry
					.getValue();
				Set<Integer> indexes = obfuscationOperationRule.getIndexes();
				Operation operation = obfuscationOperationRule.getOperation();
				if (operation != null)
				{
					obfuscationOperationRule
						.setOperatedCharacter(Operation.operate(currentCharacter, operation));
				}
				Character character = obfuscationOperationRule.getCharacter();
				Character replaceWith = obfuscationOperationRule.getReplaceWith();
				if (!indexes.isEmpty() && indexes.contains(i) && operation != null)
				{
					Character operatedCharacter = Operation.operate(character, operation);
					if (currentCharacter.equals(operatedCharacter))
					{
						if ((operation.equals(Operation.UPPERCASE) && upperCase)
							|| (operation.equals(Operation.LOWERCASE) && lowerCase))
						{
							sb.append(Operation.operate(currentChar, operation, true));
						}
						else
						{
							sb.append(Operation.operate(currentChar, operation, false));

						}
						processed = true;
						continue;
					}
					if (currentCharacter.equals(replaceWith))
					{
						sb.append(character);
						processed = true;
						continue;
					}
				}
				if (currentCharacter.equals(replaceWith) && rules.containsKey(replaceWith))
				{
					sb.append(character);
					processed = true;
					continue;
				}
			}
			if (!processed && !rules.containsKey(currentCharacter))
			{
				sb.append(currentChar);
			}
		}
		return sb.toString();
	}

	/**
	 * Validate the given {@link BiMap} if a before obfuscated String can be disentangled
	 *
	 * @param rules
	 *            the rules
	 * @return if true is returned the given {@link BiMap} is disentanglable
	 */
	public static boolean validate(
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules)
	{
		Set<Character> keySet = rules.keySet();
		for (Entry<Character, ObfuscationOperationRule<Character, Character>> entry : rules
			.entrySet())
		{
			ObfuscationOperationRule<Character, Character> value = entry.getValue();
			Character operatedCharacter = Operation.operate(value.getCharacter(),
				value.getOperation());
			if (keySet.contains(operatedCharacter))
			{
				return false;
			}
		}
		return true;
	}

}
