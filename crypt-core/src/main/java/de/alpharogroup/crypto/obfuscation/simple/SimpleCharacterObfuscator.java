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

import com.google.common.collect.BiMap;

import de.alpharogroup.check.Check;
import de.alpharogroup.crypto.obfuscation.api.Obfuscatable;
import de.alpharogroup.crypto.obfuscation.rule.ObfuscationRule;
import lombok.AccessLevel;
import lombok.NonNull;
import lombok.experimental.FieldDefaults;

/**
 * The class {@link SimpleCharacterObfuscator} provide as the name says obfuscation of a given text
 */
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class SimpleCharacterObfuscator implements Obfuscatable
{

	/** The key. */
	String key;

	/** The rule. */
	BiMap<Character, ObfuscationRule<Character, Character>> rules;
	
	BiMap<Character, Character> biMap;

	/**
	 * Instantiates a new {@link SimpleCharacterObfuscator}
	 *
	 * @param rules
	 *            the rules
	 * @param key
	 *            the key
	 */
	public SimpleCharacterObfuscator(
		final @NonNull BiMap<Character, ObfuscationRule<Character, Character>> rules,
		final @NonNull String key)
	{
		Check.get().notEmpty(rules, "rules");
		Check.get().notEmpty(key, "key");
		this.rules = rules;
		this.biMap = SimpleObfuscatorExtensions.toCharacterBiMap(rules);
		this.key = key;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String disentangle()
	{
		final String obfuscated = SimpleObfuscatorExtensions.obfuscateWith(rules, this.key);
		final String disentangled = SimpleObfuscatorExtensions.disentangle(rules, obfuscated);
		return disentangled;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String obfuscate()
	{
		final String obfuscated = SimpleObfuscatorExtensions.obfuscateWith(rules, this.key);
		return obfuscated;
	}

}
