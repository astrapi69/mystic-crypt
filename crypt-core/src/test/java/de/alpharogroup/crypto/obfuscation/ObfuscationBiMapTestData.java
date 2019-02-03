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
package de.alpharogroup.crypto.obfuscation;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import lombok.experimental.UtilityClass;

/**
 * The class {@link ObfuscationBiMapTestData} provides test data for test the obfuscation rules
 */
@UtilityClass
public class ObfuscationBiMapTestData
{

	/**
	 * Gets the {@link BiMap} for obfuscation operation rules with only three operation rules for
	 * use in unit tests.
	 *
	 * @return the {@link BiMap} for obfuscation operation rules with only three operation rules
	 */
	public static BiMap<Character, Character> getSmallBiMapRules()
	{
		Character character;
		Character replaceWith;
		BiMap<Character, Character> rules;
		rules = HashBiMap.create();

		character = 'a';
		replaceWith = 'b';
		rules.put(character, replaceWith);

		character = 'b';
		replaceWith = 'c';
		rules.put(character, replaceWith);

		character = 'c';
		replaceWith = 'd';
		rules.put(character, replaceWith);
		return rules;
	}

	/**
	 * Gets the {@link BiMap} for obfuscation rules with only two rules for use in unit tests.
	 *
	 * @return the {@link BiMap} for obfuscation rules with only two rules
	 */
	public static BiMap<Character, Character> getSmallestBiMapObfuscationRules()
	{
		Character character;
		Character replaceWith;
		BiMap<Character, Character> rules;
		rules = HashBiMap.create();

		character = Character.valueOf('a');
		replaceWith = 'b';
		rules.put(character, replaceWith);

		character = Character.valueOf('c');
		replaceWith = 'e';
		rules.put(character, replaceWith);
		return rules;
	}

	/**
	 * Gets the {@link BiMap} for obfuscation operation rules with 26 rules for use in unit tests.
	 *
	 * @return the {@link BiMap} for obfuscation operation rules with 26 rules
	 */
	public static BiMap<Character, Character> getFirstBiMapObfuscationOperationRules()
	{
		Character character;
		Character replaceWith;
		BiMap<Character, Character> rules;
		rules = HashBiMap.create();

		character = Character.valueOf('a');
		replaceWith = 'b';
		rules.put(character, replaceWith);

		character = Character.valueOf('b');
		replaceWith = 'c';
		rules.put(character, replaceWith);

		character = Character.valueOf('c');
		replaceWith = 'd';
		rules.put(character, replaceWith);

		character = Character.valueOf('d');
		replaceWith = 'e';
		rules.put(character, replaceWith);

		character = Character.valueOf('e');
		replaceWith = 'f';
		rules.put(character, replaceWith);

		character = Character.valueOf('f');
		replaceWith = 'g';
		rules.put(character, replaceWith);

		character = Character.valueOf('g');
		replaceWith = 'h';
		rules.put(character, replaceWith);

		character = Character.valueOf('h');
		replaceWith = 'i';
		rules.put(character, replaceWith);

		character = Character.valueOf('i');
		replaceWith = 'j';
		rules.put(character, replaceWith);

		character = Character.valueOf('j');
		replaceWith = 'k';
		rules.put(character, replaceWith);

		character = Character.valueOf('k');
		replaceWith = 'l';
		rules.put(character, replaceWith);

		character = Character.valueOf('l');
		replaceWith = 'm';
		rules.put(character, replaceWith);

		character = Character.valueOf('m');
		replaceWith = 'n';
		rules.put(character, replaceWith);

		character = Character.valueOf('n');
		replaceWith = 'o';
		rules.put(character, replaceWith);

		character = Character.valueOf('o');
		replaceWith = 'p';
		rules.put(character, replaceWith);

		character = Character.valueOf('p');
		replaceWith = 'q';
		rules.put(character, replaceWith);

		character = Character.valueOf('q');
		replaceWith = 'r';
		rules.put(character, replaceWith);

		character = Character.valueOf('r');
		replaceWith = 's';
		rules.put(character, replaceWith);

		character = Character.valueOf('s');
		replaceWith = 't';
		rules.put(character, replaceWith);

		character = Character.valueOf('t');
		replaceWith = 'u';
		rules.put(character, replaceWith);

		character = Character.valueOf('u');
		replaceWith = 'v';
		rules.put(character, replaceWith);

		character = Character.valueOf('v');
		replaceWith = 'w';
		rules.put(character, replaceWith);

		character = Character.valueOf('w');
		replaceWith = 'x';
		rules.put(character, replaceWith);

		character = Character.valueOf('x');
		replaceWith = 'y';
		rules.put(character, replaceWith);

		character = Character.valueOf('y');
		replaceWith = 'z';
		rules.put(character, replaceWith);

		character = Character.valueOf('z');
		replaceWith = '0';
		rules.put(character, replaceWith);
		return rules;
	}

}
