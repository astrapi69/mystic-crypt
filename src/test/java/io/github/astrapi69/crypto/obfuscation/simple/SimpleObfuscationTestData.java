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
package io.github.astrapi69.crypto.obfuscation.simple;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import io.github.astrapi69.crypto.obfuscation.rule.ObfuscationRule;

/**
 * The class {@link SimpleObfuscationTestData} provides test data for test the obfuscation rules
 */
public final class SimpleObfuscationTestData
{

	/**
	 * Gets the {@link BiMap} for obfuscation rules with 26 rules for use in unit tests.
	 *
	 * @return the {@link BiMap} for obfuscation rules with 26 rules
	 */
	public static BiMap<Character, ObfuscationRule<Character, Character>> getFirstBiMapObfuscationRules()
	{
		Character character;
		Character replaceWith;
		ObfuscationRule<Character, Character> rule;
		BiMap<Character, ObfuscationRule<Character, Character>> rules;

		rules = HashBiMap.create();

		character = Character.valueOf('a');
		replaceWith = 'b';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('b');
		replaceWith = 'c';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('c');
		replaceWith = 'd';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('d');
		replaceWith = 'e';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('e');
		replaceWith = 'f';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('f');
		replaceWith = 'g';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('g');
		replaceWith = 'h';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('h');
		replaceWith = 'i';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('i');
		replaceWith = 'j';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('j');
		replaceWith = 'k';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('k');
		replaceWith = 'l';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('l');
		replaceWith = 'm';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('m');
		replaceWith = 'n';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('n');
		replaceWith = 'o';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('o');
		replaceWith = 'p';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('p');
		replaceWith = 'q';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('q');
		replaceWith = 'r';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('r');
		replaceWith = 's';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('s');
		replaceWith = 't';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('t');
		replaceWith = 'u';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('u');
		replaceWith = 'v';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('v');
		replaceWith = 'w';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('w');
		replaceWith = 'x';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('x');
		replaceWith = 'y';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('y');
		replaceWith = 'z';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('z');
		replaceWith = '0';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);
		return rules;
	}

	/**
	 * Gets the {@link BiMap} for obfuscation rules with only three rules for use in unit tests.
	 *
	 * @return the {@link BiMap} for obfuscation rules with only three rules
	 */
	public static BiMap<Character, ObfuscationRule<Character, Character>> getSmallBiMapObfuscationRules()
	{
		Character character;
		Character replaceWith;
		ObfuscationRule<Character, Character> rule;
		BiMap<Character, ObfuscationRule<Character, Character>> rules;

		rules = HashBiMap.create();

		character = Character.valueOf('a');
		replaceWith = 'b';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('b');
		replaceWith = 'c';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('c');
		replaceWith = 'd';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);
		return rules;
	}

	/**
	 * Gets the {@link BiMap} for obfuscation rules with only two rules for use in unit tests.
	 *
	 * @return the {@link BiMap} for obfuscation rules with only two rules
	 */
	public static BiMap<Character, ObfuscationRule<Character, Character>> getSmallestBiMapObfuscationRules()
	{
		Character character;
		Character replaceWith;
		ObfuscationRule<Character, Character> rule;
		BiMap<Character, ObfuscationRule<Character, Character>> rules;

		rules = HashBiMap.create();

		character = Character.valueOf('a');
		replaceWith = 'b';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);

		character = Character.valueOf('c');
		replaceWith = 'e';
		rule = ObfuscationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).build();
		rules.put(character, rule);
		return rules;
	}

	private SimpleObfuscationTestData()
	{
	}

}
