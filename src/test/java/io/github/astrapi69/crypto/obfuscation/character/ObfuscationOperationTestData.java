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

import java.util.Set;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import de.alpharogroup.collections.set.SetFactory;
import io.github.astrapi69.crypto.obfuscation.rule.ObfuscationOperationRule;
import io.github.astrapi69.crypto.obfuscation.rule.Operation;

/**
 * The class {@link ObfuscationOperationTestData} provides test data for test the obfuscation rules
 */
public final class ObfuscationOperationTestData
{

	private ObfuscationOperationTestData()
	{
	}

	/**
	 * Gets the {@link BiMap} for obfuscation operation rules with 25 rules for use in unit tests.
	 *
	 * @return the {@link BiMap} for obfuscation operation rules with 25 rules
	 */
	public static BiMap<Character, ObfuscationOperationRule<Character, Character>> getFirstBiMapObfuscationOperationRules()
	{
		Character character;
		Set<Integer> indexes;
		Operation operation;
		Character replaceWith;
		ObfuscationOperationRule<Character, Character> rule;
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules;

		rules = HashBiMap.create();

		character = Character.valueOf('a');
		replaceWith = 'b';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0, 2);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('b');
		replaceWith = 'c';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(2);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('c');
		replaceWith = 'd';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(3);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('d');
		replaceWith = 'e';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('e');
		replaceWith = 'f';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('f');
		replaceWith = 'g';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('g');
		replaceWith = 'h';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('h');
		replaceWith = 'i';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('i');
		replaceWith = 'j';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('j');
		replaceWith = 'k';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('k');
		replaceWith = 'l';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('l');
		replaceWith = 'm';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('m');
		replaceWith = 'n';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('n');
		replaceWith = 'o';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('o');
		replaceWith = 'p';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('p');
		replaceWith = 'q';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('q');
		replaceWith = 'r';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('r');
		replaceWith = 's';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('s');
		replaceWith = 't';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('t');
		replaceWith = 'u';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('u');
		replaceWith = 'v';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('v');
		replaceWith = 'w';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('w');
		replaceWith = 'x';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('x');
		replaceWith = 'y';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('y');
		replaceWith = 'z';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('z');
		replaceWith = '0';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);
		return rules;
	}

	/**
	 * Gets the {@link BiMap} for obfuscation operation rules with only three operation rules for
	 * use in unit tests.
	 *
	 * @return the {@link BiMap} for obfuscation operation rules with only three operation rules
	 */
	public static BiMap<Character, ObfuscationOperationRule<Character, Character>> getSmallBiMapObfuscationOperationRules()
	{
		Character character;
		Set<Integer> indexes;
		Operation operation;
		Character replaceWith;
		ObfuscationOperationRule<Character, Character> rule;
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules;

		rules = HashBiMap.create();

		character = Character.valueOf('a');
		replaceWith = 'b';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0, 2);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('b');
		replaceWith = 'c';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(2);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('c');
		replaceWith = 'd';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(3);
		rule = ObfuscationOperationRule.<Character, Character> builder().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);
		return rules;
	}

}
