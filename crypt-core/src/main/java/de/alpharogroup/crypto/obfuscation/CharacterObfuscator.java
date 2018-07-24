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
package de.alpharogroup.crypto.obfuscation;

import java.util.Set;

import com.google.common.collect.BiMap;

import de.alpharogroup.check.Check;
import de.alpharogroup.crypto.obfuscation.api.Obfuscatable;
import de.alpharogroup.crypto.obfuscation.experimental.ObfuscatorExtensions;
import de.alpharogroup.crypto.obfuscation.rule.ObfuscationOperationRule;
import de.alpharogroup.crypto.obfuscation.rule.Operation;
import lombok.NonNull;

/**
 * The class {@link CharacterObfuscator}
 */
public class CharacterObfuscator implements Obfuscatable
{

	/** The rule. */
	private final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules;

	/** The key. */
	private final String key;

	public CharacterObfuscator(
		final @NonNull BiMap<Character, ObfuscationOperationRule<Character, Character>> rules,
		final @NonNull String key)
	{
		Check.get().notEmpty(rules, "rules");
		Check.get().notEmpty(key, "key");
		this.rules = rules;
		this.key = key;
	}

	@Override
	public String disentangle()
	{
		final String obfuscated = ObfuscatorExtensions.obfuscateWith(rules, this.key);
		final String disentangled = disentangleWith(rules, obfuscated);
		return disentangled;
	}

	private String disentangleWith(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules,
		final String obfuscated)
	{
		final BiMap<ObfuscationOperationRule<Character, Character>, Character> inverse = rules
			.inverse();
		final StringBuilder sb = new StringBuilder();
		for (int i = 0; i < obfuscated.length(); i++)
		{
			final char currentCharacter = obfuscated.charAt(i);
			final Character asCharacter = Character.valueOf(currentCharacter);
			final ObfuscationOperationRule<Character, Character> obfuscationOperationRule = get(
				inverse, asCharacter, i);
			if (obfuscationOperationRule != null)
			{
				final Set<Integer> indexes = obfuscationOperationRule.getIndexes();
				final Operation operation = obfuscationOperationRule.getOperation();
				final Character character = obfuscationOperationRule.getCharacter();
				if (indexes.contains(Integer.valueOf(i)) && operation != null)
				{
					sb.append(Operation.operate(currentCharacter, operation, true));
				}
				else
				{
					sb.append(character);
				}
			}
			else
			{
				sb.append(currentCharacter);
			}
		}
		return sb.toString();
	}

	private ObfuscationOperationRule<Character, Character> get(
		final BiMap<ObfuscationOperationRule<Character, Character>, Character> inverse,
		final Character found, final int index)
	{
		for (final ObfuscationOperationRule<Character, Character> obfuscationOperationRule : inverse
			.keySet())
		{
			final Set<Integer> indexes = obfuscationOperationRule.getIndexes();
			final Operation operation = obfuscationOperationRule.getOperation();
			final Character character = obfuscationOperationRule.getCharacter();
			if (indexes.contains(Integer.valueOf(index)) && operation != null)
			{
				final Character operated = Operation.operate(found, operation, true);
				if (operated.equals(character))
				{
					return obfuscationOperationRule;
				}
			}
			final Character replaceWith = obfuscationOperationRule.getReplaceWith();
			if (replaceWith.equals(found))
			{
				return obfuscationOperationRule;
			}
		}
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String obfuscate()
	{
		final String obfuscated = ObfuscatorExtensions.obfuscateWith(rules, this.key);
		return obfuscated;
	}

}
