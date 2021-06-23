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
package io.github.astrapi69.crypto.obfuscation.character;

import java.util.Objects;

import com.google.common.collect.BiMap;

import io.github.astrapi69.check.Check;
import io.github.astrapi69.crypto.obfuscation.api.Obfuscatable;
import io.github.astrapi69.crypto.obfuscation.rule.ObfuscationOperationRule;

/**
 * The class {@link CharacterObfuscator}
 */
public class CharacterObfuscator implements Obfuscatable
{
	/** The key. */
	private final String key;
	/** The rule. */
	private final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules;
	boolean disentanglable;

	public CharacterObfuscator(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules,
		final String key)
	{
		this(rules, key, false);
	}

	public CharacterObfuscator(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules,
		final String key, final boolean validate)
	{
		Objects.requireNonNull(rules);
		Objects.requireNonNull(key);
		Check.get().notEmpty(rules, "rules");
		Check.get().notEmpty(key, "key");
		this.rules = rules;
		this.key = key;
		if (validate)
		{
			this.disentanglable = ObfuscatorExtensions.validate(this.rules);
		}
	}

	@Override
	public String disentangle()
	{
		return ObfuscatorExtensions.disentangle(rules, obfuscate());
	}

	public boolean isDisentanglable()
	{
		return this.disentanglable;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String obfuscate()
	{
		return ObfuscatorExtensions.obfuscateWith(rules, this.key);
	}
}
