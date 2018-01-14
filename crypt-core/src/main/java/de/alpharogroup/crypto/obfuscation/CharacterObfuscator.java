package de.alpharogroup.crypto.obfuscation;

import java.util.Set;

import com.google.common.collect.BiMap;
import de.alpharogroup.check.Check;
import de.alpharogroup.crypto.obfuscation.api.Obfuscatable;
import de.alpharogroup.crypto.obfuscation.rule.ObfuscationOperationRule;
import de.alpharogroup.crypto.obfuscation.rule.Operation;

public class CharacterObfuscator implements Obfuscatable
{
	/** The rule. */
	private final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules;

	/** The key. */
	private final String key;

	public CharacterObfuscator(final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules, final String key)
	{
		Check.get().notEmpty(rules, "rules");
		Check.get().notEmpty(key, "key");
		this.rules = rules;
		this.key = key;
	}

	@Override public String disentangle()
	{
		final String obfuscated = obfuscateWith(rules, this.key);
		String disentangled = disentangleWith(rules, obfuscated);
		return disentangled;
	}

	private String disentangleWith(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules, final String obfuscated)
	{
		final BiMap<ObfuscationOperationRule<Character, Character>, Character> inverse = rules.inverse();
		Character repl;
		final Character found = 'x';
		final StringBuilder sb = new StringBuilder();
		for (int i = 0; i < obfuscated.length(); i++)
		{
			final char currentCharacter = obfuscated.charAt(i);
			final Character asCharacter = Character.valueOf(currentCharacter);
			ObfuscationOperationRule<Character, Character> obfuscationOperationRule = get(
				inverse, asCharacter, i);
			if (obfuscationOperationRule !=null) {
				final Set<Integer> indexes = obfuscationOperationRule.getIndexes();
				final Operation operation = obfuscationOperationRule.getOperation();
				Character character = obfuscationOperationRule.getCharacter();
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

	private ObfuscationOperationRule<Character, Character> get(BiMap<ObfuscationOperationRule<Character, Character>, Character> inverse,
		Character found, int index)
	{
		for (final ObfuscationOperationRule<Character, Character> obfuscationOperationRule : inverse
			.keySet())
		{
			final Set<Integer> indexes = obfuscationOperationRule.getIndexes();
			final Operation operation = obfuscationOperationRule.getOperation();
			Character character = obfuscationOperationRule.getCharacter();
			if (indexes.contains(Integer.valueOf(index)) && operation != null) {
				Character operated = Operation.operate(found, operation, true);
				if(operated.equals(character)){
					return obfuscationOperationRule;
				}
			}
			final Character replaceWith = obfuscationOperationRule.getReplaceWith();
			if(replaceWith.equals(found)) {
				return obfuscationOperationRule;
			}
		}
		return null;
	}

	@Override public String obfuscate()
	{
		final String obfuscated = obfuscateWith(rules, this.key);
		return obfuscated;
	}


	public static String obfuscateWith(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules, final String toObfuscate)
	{
		final StringBuilder sb = new StringBuilder();
		for (int i = 0; i < toObfuscate.length(); i++)
		{
			final char currentCharacter = toObfuscate.charAt(i);
			final Character asCharacter = Character.valueOf(currentCharacter);
			final String charAsString = Character.toString(currentCharacter);
			if (rules.containsKey(asCharacter))
			{
				final ObfuscationOperationRule<Character, Character> obfuscationOperationRule = rules
					.get(asCharacter);
				final Set<Integer> indexes = obfuscationOperationRule.getIndexes();
				final Operation operation = obfuscationOperationRule.getOperation();
				if (indexes.contains(Integer.valueOf(i)) && operation != null)
				{
					sb.append(Operation.operate(currentCharacter, operation));
					continue;
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

}
