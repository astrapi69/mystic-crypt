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
package de.alpharogroup.crypto.obfuscation;

import java.util.Map;

import org.apache.commons.lang3.StringUtils;

import de.alpharogroup.check.Check;
import de.alpharogroup.crypto.keyrules.KeyMapObfuscationRules;
import de.alpharogroup.crypto.obfuscation.api.Obfuscatable;

/**
 * The Class {@link Obfuscator} obfuscates the given {@link KeyMapObfuscationRules}. For an example see the
 * unit test.
 */
public class Obfuscator implements Obfuscatable
{

	/** The rule. */
	private final KeyMapObfuscationRules rule;

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
	public Obfuscator(final KeyMapObfuscationRules rule, final String key)
	{
		Check.get().notNull(rule, "rule");
		Check.get().notEmpty(key, "key");
		this.rule = rule;
		this.key = key;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
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
	 * {@inheritDoc}
	 */
	@Override
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
