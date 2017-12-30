package de.alpharogroup.crypto.obfuscation;

import java.util.List;
import java.util.Map;

import de.alpharogroup.check.Check;
import de.alpharogroup.collections.pairs.ValueBox;
import de.alpharogroup.crypto.obfuscation.api.Obfuscatable;
import de.alpharogroup.crypto.obfuscation.rule.ComplexObfuscationRule;
import de.alpharogroup.crypto.obfuscation.rule.ObfuscationRules;
import de.alpharogroup.crypto.obfuscation.rules.ComplexObfuscationKeyMapRules;

public class ComplexObfuscator implements Obfuscatable
{
	private final ComplexObfuscationKeyMapRules rules;

	/** The key. */
	private final String key;

	public ComplexObfuscator(ComplexObfuscationKeyMapRules rules, final String key)
	{
		Check.get().notNull(rules, "rule");
		Check.get().notEmpty(key, "key");
		this.rules = rules;
		this.key = key;
	}

	@Override
	public String disentangle()
	{
		return null;
	}

	@Override
	public String obfuscate()
	{
		final Map<Character, ComplexObfuscationRule> obfuscationRules = this.rules.getObfuscationRules();

		final ValueBox<Integer> count = ValueBox.<Integer>builder()
			.value(0)
			.build();
		final StringBuilder sb = new StringBuilder();
		this.key.chars()
        .mapToObj(i -> (char)i)
		.forEach(i -> {
			char current = i;
			ComplexObfuscationRule complexObfuscationRule = obfuscationRules.get(Character.valueOf(current));
			if(complexObfuscationRule != null) {
				ObfuscationRules replaceWithRules = complexObfuscationRule.getReplaceWithRules();
				if(replaceWithRules != null && replaceWithRules.getRules() != null && !replaceWithRules.getRules().isEmpty()) {
					List<Object> rules2 = replaceWithRules.getRules();
					for (Object object : rules2)
					{
						sb.append(object);
					}
				} else {
					sb.append(current);
				}
			} else {
				sb.append(current);
			}

			Integer currentValue=count.getValue();
			System.out.println(currentValue + ":" + current);
			count.setValue(++currentValue);
			});
		return sb.toString();
	}

}
