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
package de.alpharogroup.crypto.obfuscation.experimental;

import de.alpharogroup.check.Check;
import de.alpharogroup.crypto.obfuscation.api.Obfuscatable;
import de.alpharogroup.crypto.obfuscation.rules.SimpleObfuscationRules;

/**
 * The Class {@link StringObfuscator} obfuscates the given {@link SimpleObfuscationRules}. For an
 * example see the unit test.
 */
public class StringObfuscator implements Obfuscatable
{

	/** The rule. */
	private final SimpleObfuscationRules rule;

	/** The key. */
	private final String key;

	/**
	 * Instantiates a new {@link StringObfuscator}.
	 *
	 * @param rule
	 *            the rule
	 * @param key
	 *            the key
	 */
	public StringObfuscator(final SimpleObfuscationRules rule, final String key)
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
		return ObfuscatorExtensions.disentangle(rule.getObfuscationRules(), obfuscate());
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String obfuscate()
	{
		return ObfuscatorExtensions.obfuscate(rule.getObfuscationRules(), key);
	}

}
