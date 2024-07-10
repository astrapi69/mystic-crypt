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

import java.util.Objects;

import com.google.common.collect.BiMap;

import io.github.astrapi69.check.Check;
import io.github.astrapi69.crypt.api.obfuscation.Obfuscatable;
import io.github.astrapi69.crypt.data.obfuscation.rule.ObfuscationOperationRule;

/**
 * Provides methods for obfuscating and disentangling character sequences based on predefined rules.
 * This class implements the {@link Obfuscatable} interface, supporting the obfuscation and
 * potentially reversible disentanglement of text using a bidirectional map of obfuscation rules.
 *
 * <p>
 * Initialization of this class is dependent on a set of {@link ObfuscationOperationRule}s and a key
 * which are mandatory for its operations. Optionally, the constructor can validate the possibility
 * of disentanglement based on the provided rules and the key.
 * </p>
 *
 * <h2>Usage:</h2>
 * 
 * <pre>
 * BiMap&lt;Character, ObfuscationOperationRule&lt;Character, Character&gt;&gt; rules = HashBiMap.create();
 * rules.put('a', new ObfuscationOperationRule&lt;e&lt;('a', 'x'));
 * CharacterObfuscator obfuscator = new CharacterObfuscator(rules, "someKey", true);
 * </pre>
 *
 * @author Asterios Raptis
 * @version 1.0
 * @since 2015
 * @see Obfuscatable
 * @see ObfuscationOperationRule
 * @see BiMap
 */
public class CharacterObfuscator implements Obfuscatable
{
	/**
	 * The key used for obfuscation operations.
	 */
	private final String key;

	/**
	 * Mapping of characters to their corresponding obfuscation rules.
	 */
	private final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules;

	/**
	 * Indicates whether the obfuscation can be reversed using the current rules and key.
	 */
	private boolean disentanglable;

	/**
	 * Constructs a new {@code CharacterObfuscator} instance with the specified rules and key.
	 * Disentanglement validation is not performed by default.
	 *
	 * @param rules
	 *            the character to rule bi-directional map, must not be empty
	 * @param key
	 *            the key for obfuscation, must not be empty
	 * @throws NullPointerException
	 *             if rules or key are null
	 */
	public CharacterObfuscator(
		final BiMap<Character, ObfuscationOperationRule<Character, Character>> rules,
		final String key)
	{
		this(rules, key, false);
	}

	/**
	 * Constructs a new {@code CharacterObfuscator} with validation option. This constructor allows
	 * enabling the validation check for reversible obfuscation based on the provided rules.
	 *
	 * @param rules
	 *            the character to rule bi-directional map, must not be empty
	 * @param key
	 *            the key for obfuscation, must not be empty
	 * @param validate
	 *            if {@code true}, checks if disentanglement is possible
	 * @throws NullPointerException
	 *             if rules or key are null
	 */
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

	/**
	 * Disentangles the obfuscated output based on the rules.
	 *
	 * @return the original text if disentanglement is possible, otherwise an unspecified string
	 */
	@Override
	public String disentangle()
	{
		return ObfuscatorExtensions.disentangle(rules, obfuscate());
	}

	/**
	 * Checks if the current configuration supports reversible obfuscation.
	 *
	 * @return {@code true} if disentanglement is feasible, {@code false} otherwise
	 */
	public boolean isDisentanglable()
	{
		return this.disentanglable;
	}

	/**
	 * Obfuscates the text based on the provided rules and key.
	 *
	 * @return the obfuscated text
	 */
	@Override
	public String obfuscate()
	{
		return ObfuscatorExtensions.obfuscateWith(rules, this.key);
	}
}
