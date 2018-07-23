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
package de.alpharogroup.crypto.obfuscation.experimental;

import java.util.Set;

import com.google.common.collect.BiMap;

import de.alpharogroup.check.Check;
import de.alpharogroup.crypto.obfuscation.CharacterObfuscator;
import de.alpharogroup.crypto.obfuscation.api.Obfuscatable;
import de.alpharogroup.crypto.obfuscation.rule.ObfuscationOperationRule;
import de.alpharogroup.crypto.obfuscation.rule.Operation;

/**
 * The class {@link ComplexObfuscator}.
 * 
 * @deprecated use instead the {@link CharacterObfuscator} <br>
 *             <br>
 *             Note: will be removed on next minor release.
 */
@Deprecated
public class ComplexObfuscator implements Obfuscatable
{

	public static String obfuscateWith(
		final BiMap<Character, ObfuscationOperationRule<Character, String>> rules,
		final String toObfuscate)
	{
		final StringBuilder sb = new StringBuilder();
		for (int i = 0; i < toObfuscate.length(); i++)
		{
			final char currentCharacter = toObfuscate.charAt(i);
			final Character asCharacter = Character.valueOf(currentCharacter);
			if (rules.containsKey(asCharacter))
			{
				final ObfuscationOperationRule<Character, String> obfuscationOperationRule = rules
					.get(asCharacter);
				final Set<Integer> indexes = obfuscationOperationRule.getIndexes();
				final Operation operation = obfuscationOperationRule.getOperation();
				if (indexes.contains(Integer.valueOf(i)) && operation != null)
				{
					sb.append(Operation.operate(currentCharacter, operation));
				}
				else
				{
					final String replaceWith = obfuscationOperationRule.getReplaceWith();
					sb.append(replaceWith);
				}
			}
			else
			{
				sb.append(currentCharacter);
			}
		}
		return sb.toString();
	}

	/** The rule. */
	private final BiMap<Character, ObfuscationOperationRule<Character, String>> rules;

	/** The key. */
	private final String key;

	public ComplexObfuscator(
		final BiMap<Character, ObfuscationOperationRule<Character, String>> rules, final String key)
	{
		Check.get().notEmpty(rules, "rules");
		Check.get().notEmpty(key, "key");
		this.rules = rules;
		this.key = key;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String disentangle()
	{
		return key;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String obfuscate()
	{
		final String obfuscated = obfuscateWith(rules, this.key);
		return obfuscated;
	}

}
