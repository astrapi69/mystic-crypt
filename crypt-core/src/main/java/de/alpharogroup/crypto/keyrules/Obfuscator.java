/**
 * Copyright (C) 2007 Asterios Raptis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.alpharogroup.crypto.keyrules;

import java.util.Map;

import org.apache.commons.lang.StringUtils;

import de.alpharogroup.check.Check;

/**
 * The Class {@link Obfuscator} obfuscates the given {@link SimpleKeyRule}.
 */
public class Obfuscator
{

	/** The rule. */
	private final SimpleKeyRule rule;

	/** The key. */
	private final String key;

	/**
	 * Instantiates a new {@link Obfuscator}.
	 *
	 * @param rule
	 *            the rule
	 * @param key
	 *            the key
	 */
	public Obfuscator(final SimpleKeyRule rule, final String key)
	{
		Check.get().notNull(rule, "rule");
		Check.get().notEmpty(key, "key");
		this.rule = rule;
		this.key = key;
	}

	/**
	 * Disentangle.
	 *
	 * @return the string
	 */
	public String disentangle()
	{
		String clonedKey = obfuscate();
		final Map<String, String> rules = rule.getRules();
		for (final Map.Entry<String, String> rule : rules.entrySet())
		{
			clonedKey = StringUtils.replace(clonedKey, rule.getValue(), rule.getKey());
		}
		return clonedKey;
	}

	/**
	 * Obfuscate.
	 *
	 * @return the string
	 */
	public String obfuscate()
	{
		final Map<String, String> rules = rule.getRules();
		String clonedKey = key;
		for (final Map.Entry<String, String> rule : rules.entrySet())
		{
			clonedKey = StringUtils.replace(clonedKey, rule.getKey(), rule.getValue());
		}
		return clonedKey;

	}

}
