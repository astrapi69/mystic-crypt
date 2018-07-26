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
package de.alpharogroup.crypto.obfuscation.experimental;

import static org.testng.AssertJUnit.assertEquals;

import java.lang.reflect.InvocationTargetException;
import java.util.Set;

import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import de.alpharogroup.AbstractTestCase;
import de.alpharogroup.collections.set.SetFactory;
import de.alpharogroup.crypto.obfuscation.rule.ObfuscationOperationRule;
import de.alpharogroup.crypto.obfuscation.rule.Operation;

/**
 * The unit test class for the class {@link ObfuscatorExtensions}
 */
public class ObfuscatorExtensionsTest extends AbstractTestCase<String, String>
{

	Character character;
	Set<Integer> indexes;
	Operation operation;
	Character replaceWith;
	ObfuscationOperationRule<Character, Character> rule;
	BiMap<Character, ObfuscationOperationRule<Character, Character>> rules;
	String stringToObfuscate;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 *
	 * @throws Exception
	 *             is thrown if an exception occurs
	 */
	@BeforeMethod
	protected void setUp() throws Exception
	{
		super.setUp();
		// create a rule for obfuscate the key
		rules = HashBiMap.create();

		character = Character.valueOf('a');
		replaceWith = 'b';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0, 2);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('b');
		replaceWith = 'c';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(2);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('c');
		replaceWith = 'd';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(3);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

	}

	/**
	 * Test method for {@link ObfuscatorExtensions#obfuscateWith(BiMap, String)}
	 */
	@Test
	public void testObfuscateWith()
	{
		// new scenario...
		stringToObfuscate = "abac";

		actual = ObfuscatorExtensions.obfuscateWith(rules, stringToObfuscate);
		expected = "AcAC";
		assertEquals(expected, actual);
		// new scenario...
		stringToObfuscate = "abacd";

		actual = ObfuscatorExtensions.obfuscateWith(rules, stringToObfuscate);
		expected = "AcACd";
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link ObfuscatorExtensions} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(ObfuscatorExtensions.class);
	}

}
