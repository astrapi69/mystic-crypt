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
package io.github.astrapi69.mystic.crypt.obfuscation.character;

import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import io.github.astrapi69.clone.CloneObjectExtensions;
import io.github.astrapi69.collection.map.MapFactory;
import io.github.astrapi69.collection.pair.KeyValuePair;
import io.github.astrapi69.crypt.api.obfuscation.rule.Operation;
import io.github.astrapi69.crypt.data.obfuscation.rule.ObfuscationOperationRule;

/**
 * The class {@link ObfuscatorExtensions} provides algorithms to obfuscate and disentangle strings.
 */
public final class ObfuscatorExtensions
{

	private ObfuscatorExtensions()
	{
	}

	/**
	 * Disentangle the given obfuscated text using the specified {@link BiMap} rules
	 *
	 * @param rules
	 *            the rules
	 * @param obfuscated
	 *            the obfuscated text
	 * @return the disentangled string
	 */
	public static String disentangle(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules,
		final String obfuscated)
	{
		Objects.requireNonNull(rules);
		Objects.requireNonNull(obfuscated);
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
					obfuscationOperationRule.setOperatedCharacter(
						Optional.of(Operation.operate(currentCharacter, operation)));
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
	 * Disentangle the given obfuscated text using the specified {@link List} rules
	 *
	 * @param rules
	 *            the rules
	 * @param obfuscated
	 *            the obfuscated text
	 * @return the disentangled string
	 */
	public static String disentangle(
		final List<KeyValuePair<Character, ObfuscationOperationRule<Character, Character>>> rules,
		final String obfuscated)
	{
		char currentChar;
		Character currentCharacter;
		final StringBuilder sb = new StringBuilder();
		Map<Character, Character> swapped = swapMapWithReplaceWithAsKey(
			HashBiMap.create(KeyValuePair.toMap(rules)));
		for (int i = 0; i < obfuscated.length(); i++)
		{
			currentChar = obfuscated.charAt(i);
			currentCharacter = currentChar;
			if (swapped.containsKey(currentCharacter))
			{
				sb.append(swapped.get(currentCharacter));
			}
			else
			{
				sb.append(currentChar);
			}
		}
		return sb.toString();
	}

	/**
	 * Disentangle the given obfuscated text using the specified {@link BiMap} rules
	 *
	 * @param rules
	 *            the rules
	 * @param obfuscated
	 *            the obfuscated text
	 * @return the disentangled string
	 */
	public static String disentangleImproved(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules,
		final String obfuscated)
	{
		char currentChar;
		Character currentCharacter;
		ObfuscationOperationRule<Character, Character> currentOperationRule;
		final StringBuilder sb = new StringBuilder();
		Map<Character, ObfuscationOperationRule<Character, Character>> swapped = swapOperatedMapWithReplaceWithAsKey(
			rules);
		BiMap<ObfuscationOperationRule<Character, Character>, Character> inverted = inverse(rules);
		BiMap<Character, ObfuscationOperationRule<Character, Character>> inverseInverted = inverted
			.inverse();
		for (int i = 0; i < obfuscated.length(); i++)
		{
			currentChar = obfuscated.charAt(i);
			currentCharacter = currentChar;
			if (inverseInverted.containsKey(currentCharacter))
			{
				currentOperationRule = inverseInverted.get(currentCharacter);
				sb.append(currentOperationRule.getReplaceWith());
			}
			else if (swapped.containsKey(currentCharacter))
			{
				currentOperationRule = swapped.get(currentCharacter);
				Set<Integer> indexes = currentOperationRule.getIndexes();
				if (!indexes.isEmpty() && indexes.contains(i))
				{
					sb.append(currentOperationRule.getCharacter());
				}
			}
			else
			{
				sb.append(currentChar);
			}
		}
		return sb.toString();
	}

	/**
	 * Inverse the given BiMap rules
	 *
	 * @param rules
	 *            the rules
	 * @return the inversed BiMap
	 */
	public static BiMap<ObfuscationOperationRule<Character, Character>, Character> inverse(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules)
	{
		Objects.requireNonNull(rules);
		BiMap<Character, ObfuscationOperationRule<Character, Character>> cloned;
		Optional<BiMap<Character, ObfuscationOperationRule<Character, Character>>> optional = tryToClone(
			rules);
		if (optional.isPresent())
		{
			cloned = optional.get();
		}
		else
		{
			cloned = rules;
		}
		BiMap<ObfuscationOperationRule<Character, Character>, Character> invertedBiMap = cloned
			.inverse();
		invertedBiMap.entrySet().forEach(entry -> {
			ObfuscationOperationRule<Character, Character> key = entry.getKey();
			inverse(key);
			entry.setValue(key.getCharacter());
		});
		return invertedBiMap;
	}

	/**
	 * Inverse the given ObfuscationOperationRule
	 *
	 * @param rule
	 *            the rule
	 */
	public static void inverse(final ObfuscationOperationRule<Character, Character> rule)
	{
		Objects.requireNonNull(rule);
		char currentChar = rule.getCharacter();
		char replaceWithChar = rule.getReplaceWith();
		rule.setCharacter(replaceWithChar);
		rule.setReplaceWith(currentChar);
		rule.setInverted(!rule.isInverted());
	}

	/**
	 * Inverse the given BiMap rules to a Map
	 *
	 * @param rules
	 *            the rules
	 * @return the inversed Map
	 */
	public static Map<ObfuscationOperationRule<Character, Character>, Character> inverseToMap(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules)
	{
		Objects.requireNonNull(rules);
		Map<ObfuscationOperationRule<Character, Character>, Character> invertedMap = new HashMap<>();
		rules.entrySet().forEach(entry -> {
			invertedMap.put(tryToClone(entry.getValue()).get(), tryToClone(entry.getKey()).get());
		});
		return invertedMap;
	}

	/**
	 * Validate if the given input can be obfuscated with the specified rules. This means if the
	 * given input is disentanglable
	 *
	 * @param rules
	 *            the rules
	 * @param input
	 *            the input
	 * @return true if the given BiMap is obfuscable with the given input otherwise false
	 */
	public static boolean isObfuscableAndDisentanglable(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules,
		final String input)
	{
		Objects.requireNonNull(rules);
		Objects.requireNonNull(input);
		if (validate(rules))
		{
			String obfuscated = obfuscateWith(rules, input);
			String disentangled = disentangle(rules, obfuscated);
			return input.equals(disentangled);
		}
		return false;
	}

	/**
	 * Obfuscate with the given BiMap
	 *
	 * @param rules
	 *            the rules
	 * @param toObfuscate
	 *            the String object to obfuscate
	 * @return the obfuscated string
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
					obfuscationOperationRule.setOperatedCharacter(
						Optional.of(Operation.operate(currentCharacter, operation)));
				}
				if (indexes.contains(i))
				{
					if (obfuscationOperationRule.getOperatedCharacter().isPresent())
					{
						sb.append(obfuscationOperationRule.getOperatedCharacter().get());
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
	 * Obfuscate with the given BiMap
	 *
	 * @param rules
	 *            the rules
	 * @param toObfuscate
	 *            the String object to obfuscate
	 * @return the obfuscated string
	 */
	public static String obfuscateWithCharArray(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules,
		final String toObfuscate)
	{
		char[] result = new char[toObfuscate.length()];
		for (int i = 0; i < toObfuscate.length(); i++)
		{
			final char currentCharacter = toObfuscate.charAt(i);
			final Character asCharacter = currentCharacter;
			if (rules.containsKey(asCharacter))
			{
				final ObfuscationOperationRule<Character, Character> obfuscationOperationRule = rules
					.get(asCharacter);
				final Set<Integer> indexes = obfuscationOperationRule.getIndexes();
				final Operation operation = obfuscationOperationRule.getOperation();
				if (operation != null && !operation.equals(Operation.NONE))
				{
					obfuscationOperationRule.setOperatedCharacter(
						Optional.of(Operation.operate(currentCharacter, operation)));
				}
				if (indexes.contains(i))
				{
					if (obfuscationOperationRule.getOperatedCharacter().isPresent())
					{
						result[i] = obfuscationOperationRule.getOperatedCharacter().get();
						continue;
					}
				}
				final Character replaceWith = obfuscationOperationRule.getReplaceWith();
				result[i] = replaceWith;
			}
			else
			{
				result[i] = currentCharacter;
			}
		}
		return new String(result);
	}

	/**
	 * Swap the given BiMap with ReplaceWith as key
	 *
	 * @param rules
	 *            the rules
	 * @return the swapped map
	 */
	public static Map<Character, Character> swapMapWithReplaceWithAsKey(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules)
	{
		Objects.requireNonNull(rules);
		Map<Character, Character> swapped = MapFactory.newLinkedHashMap();
		rules.entrySet().forEach(entry -> {
			ObfuscationOperationRule<Character, Character> value = entry.getValue();
			if (value.getOperation() != null && !value.getOperation().equals(Operation.NONE)
				&& !value.getIndexes().isEmpty())
			{
				value.setOperatedCharacter(
					Optional.of(Operation.operate(value.getCharacter(), value.getOperation())));
				swapped.put(value.getOperatedCharacter().get(), entry.getKey());
			}
			swapped.put(value.getReplaceWith(), entry.getKey());
		});
		return swapped;
	}

	/**
	 * Swap the given BiMap with Operated character as key
	 *
	 * @param rules
	 *            the rules
	 * @return the swapped map
	 */
	public static Map<Character, ObfuscationOperationRule<Character, Character>> swapOperatedMapWithReplaceWithAsKey(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules)
	{
		Objects.requireNonNull(rules);
		Map<Character, ObfuscationOperationRule<Character, Character>> swapped = MapFactory
			.newLinkedHashMap();
		rules.entrySet().forEach(entry -> {
			ObfuscationOperationRule<Character, Character> value = entry.getValue();
			if (value.getOperation() != null && !value.getOperation().equals(Operation.NONE)
				&& !value.getIndexes().isEmpty())
			{
				value.setOperatedCharacter(
					Optional.of(Operation.operate(value.getCharacter(), value.getOperation())));
				swapped.put(value.getOperatedCharacter().get(), value);
			}
			swapped.put(value.getReplaceWith(), value);
		});
		return swapped;
	}

	/**
	 * Try to clone the given object
	 *
	 * @param <T>
	 *            the type of the object
	 * @param object
	 *            the object
	 * @return the optional containing the cloned object or empty if cloning failed
	 */
	public static <T> Optional<T> tryToClone(final T object)
	{
		Objects.requireNonNull(object);
		try
		{
			return Optional.of(CloneObjectExtensions.clone(object));
		}
		catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException e)
		{
			// Do nothing
		}
		return Optional.empty();
	}

	/**
	 * Validate if the given BiMap can be disentangled after obfuscation
	 *
	 * @param rules
	 *            the rules
	 * @return true if the given BiMap is disentanglable, otherwise false
	 */
	public static boolean validate(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules)
	{
		Objects.requireNonNull(rules);
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
