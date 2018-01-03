package de.alpharogroup.crypto.obfuscation;

import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.BiMap;

import de.alpharogroup.check.Check;
import de.alpharogroup.crypto.obfuscation.api.Obfuscatable;
import de.alpharogroup.crypto.obfuscation.rule.ObfuscationOperationRule;
import de.alpharogroup.crypto.obfuscation.rule.Operation;

public class ComplexObfuscator implements Obfuscatable
{

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
		String obfuscated = obfuscate();
		BiMap<ObfuscationOperationRule<Character, String>, Character> inverse = rules.inverse();
		// search for replaceWith...
		for (final Map.Entry<ObfuscationOperationRule<Character, String>, Character> rule : inverse.entrySet())
		{
			ObfuscationOperationRule<Character, String> obfuscationOperationRule = rule.getKey();
			Character character = obfuscationOperationRule.getCharacter();
			String replaceWith = obfuscationOperationRule.getReplaceWith();
			Operation operation = obfuscationOperationRule.getOperation();
			Set<Integer> indexes = obfuscationOperationRule.getIndexes();
			if (!indexes.isEmpty() && operation != null) {
				Character operatedCharacter = operate(character, operation);
				int index = obfuscated.indexOf(replaceWith);
				if(indexes.contains(index)) {
					obfuscated = StringUtils.replace(obfuscated, operatedCharacter.toString(), character.toString());
				} else {
					obfuscated = StringUtils.replace(obfuscated, replaceWith, character.toString());
				}
			} else {
				obfuscated = StringUtils.replace(obfuscated, replaceWith, character.toString());
			}
		}
		// search for operatedCharacter...

		for (final Map.Entry<ObfuscationOperationRule<Character, String>, Character> rule : inverse.entrySet())
		{
			ObfuscationOperationRule<Character, String> obfuscationOperationRule = rule.getKey();
			Character character = obfuscationOperationRule.getCharacter();
			String replaceWith = obfuscationOperationRule.getReplaceWith();
			Operation operation = obfuscationOperationRule.getOperation();
			Set<Integer> indexes = obfuscationOperationRule.getIndexes();
			if (!indexes.isEmpty() && operation != null) {
				Character operatedCharacter = operate(character, operation);
				int index = obfuscated.indexOf(operatedCharacter.toString());
				if(indexes.contains(index)) {
					obfuscated = StringUtils.replace(obfuscated, operatedCharacter.toString(), character.toString());
				} else {
					obfuscated = StringUtils.replace(obfuscated, replaceWith, character.toString());
				}
			} else {
				obfuscated = StringUtils.replace(obfuscated, replaceWith, character.toString());
			}
		}
		return obfuscated;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String obfuscate()
	{
		String obfuscated = obfuscateWith(rules, this.key);
		return obfuscated;
	}

	public static String obfuscateWith(BiMap<Character, ObfuscationOperationRule<Character, String>> rules, String toObfuscate)
	{
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < toObfuscate.length(); i++)
		{
			char currentCharacter = toObfuscate.charAt(i);
			Character asCharacter = Character.valueOf(currentCharacter);
			String charAsString = Character.toString(currentCharacter);
			if (rules.containsKey(asCharacter))
			{
				ObfuscationOperationRule<Character, String> obfuscationOperationRule = rules
					.get(asCharacter);
				Set<Integer> indexes = obfuscationOperationRule.getIndexes();
				Operation operation = obfuscationOperationRule.getOperation();
				if (indexes.contains(Integer.valueOf(i)) && operation != null)
				{
					sb.append(operate(currentCharacter, operation));
				} else {
					String replaceWith = obfuscationOperationRule.getReplaceWith();
					sb.append(replaceWith);
				}
			}
			else
			{
				sb.append(charAsString);
			}
		}
		return sb.toString();
	}

	private static Character operate(char currentCharacter,
		Operation operation)
	{
		switch (operation)
		{
			case LOWERCASE :
				return Character.toLowerCase(currentCharacter);
			case UPPERCASE :
				return Character.toUpperCase(currentCharacter);
			case TITLECASE :
				return Character.toTitleCase(currentCharacter);
			default :
				return Character.valueOf(currentCharacter);
		}
	}


}
