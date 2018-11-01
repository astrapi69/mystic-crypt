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
package de.alpharogroup.crypto.obfuscation.simple;

import java.util.Map.Entry;
import java.util.Set;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import de.alpharogroup.crypto.obfuscation.rule.ObfuscationRule;
import lombok.NonNull;
import lombok.experimental.UtilityClass;

/**
 * The class {@link SimpleObfuscatorExtensions} provides algorithms for obfuscate strings.
 */
@UtilityClass
public class SimpleObfuscatorExtensions
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
		final BiMap<Character, ObfuscationRule<Character, Character>> rules,
		final String toObfuscate)
	{
		final StringBuilder sb = new StringBuilder();
		for (int i = 0; i < toObfuscate.length(); i++)
		{
			final char currentCharacter = toObfuscate.charAt(i);
			final Character asCharacter = Character.valueOf(currentCharacter);
			final String charAsString = Character.toString(currentCharacter);
			if (rules.containsKey(asCharacter))
			{
				final ObfuscationRule<Character, Character> obfuscationOperationRule = rules
					.get(asCharacter);
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
		final BiMap<Character, ObfuscationRule<Character, Character>> rules,
		final String obfuscated)
	{
		boolean processed = false;
		char currentChar;
		Character currentCharacter;
		final StringBuilder sb = new StringBuilder();
		for (int i = 0; i < obfuscated.length(); i++)
		{
			currentChar = obfuscated.charAt(i);
			currentCharacter = Character.valueOf(currentChar);

			for (final Entry<Character, ObfuscationRule<Character, Character>> entry : rules
				.entrySet())
			{
				ObfuscationRule<Character, Character> obfuscationRule = entry.getValue();
				Character replaceWith = obfuscationRule.getReplaceWith();
				Character character = obfuscationRule.getCharacter();
				if (currentCharacter.equals(replaceWith) && rules.containsKey(replaceWith))
				{
					sb.append(character);
					processed = true;
					break;
				}
			}
			if (!processed)
			{
				sb.append(currentChar);
			}
			processed = false;
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
	public static String disentangleBiMap(final BiMap<Character, Character> rules,
		final String obfuscated)
	{
		return obfuscateBiMap(rules.inverse(), obfuscated);
	}

	/**
	 * Obfuscate with the given {@link BiMap}
	 *
	 * @param rules
	 *            the rules
	 * @param toObfuscate
	 *            the {@link String} object to obfuscate
	 * @return the string
	 */
	public static String obfuscateBiMap(final BiMap<Character, Character> rules,
		final String toObfuscate)
	{
		char currentChar;
		Character currentCharacter;
		final StringBuilder sb = new StringBuilder();
		for (int i = 0; i < toObfuscate.length(); i++)
		{
			currentChar = toObfuscate.charAt(i);
			currentCharacter = Character.valueOf(currentChar);
			if (rules.containsKey(currentCharacter))
			{
				sb.append(rules.get(currentCharacter));
			}
			else
			{
				sb.append(currentChar);
			}
		}
		return sb.toString();
	}

	/**
	 * Transforms the given obfuscation rules {@link BiMap} to a simple character {@link BiMap}
	 *
	 * @param rules
	 *            the rules
	 * @return the simple character {@link BiMap}
	 */
	public static BiMap<Character, Character> toCharacterBiMap(
		@NonNull BiMap<Character, ObfuscationRule<Character, Character>> rules)
	{
		BiMap<Character, Character> biMap = HashBiMap.create();
		rules.keySet().stream().forEach(
			key -> biMap.put(rules.get(key).getCharacter(), rules.get(key).getReplaceWith()));
		return biMap;
	}

	/**
	 * Validate the given {@link BiMap} if a before obfuscated String can be disentangled
	 *
	 * @param rules
	 *            the rules
	 * @return if true is returned the given {@link BiMap} is disentanglable
	 */
	public static boolean validate(BiMap<Character, ObfuscationRule<Character, Character>> rules)
	{
		Set<Character> keySet = rules.keySet();
		for (Entry<Character, ObfuscationRule<Character, Character>> entry : rules.entrySet())
		{
			ObfuscationRule<Character, Character> value = entry.getValue();
			if (keySet.contains(value.getReplaceWith()))
			{
				return false;
			}
		}
		return true;
	}

}
