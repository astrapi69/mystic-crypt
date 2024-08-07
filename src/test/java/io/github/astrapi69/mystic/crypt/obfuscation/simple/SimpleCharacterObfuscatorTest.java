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
package io.github.astrapi69.mystic.crypt.obfuscation.simple;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.google.common.collect.BiMap;

import io.github.astrapi69.crypt.api.obfuscation.Obfuscatable;
import io.github.astrapi69.crypt.data.obfuscation.rule.ObfuscationRule;
import io.github.astrapi69.test.base.AbstractTestCase;

/**
 * The unit test class for the class {@link SimpleCharacterObfuscator}
 */
public class SimpleCharacterObfuscatorTest extends AbstractTestCase<String, String>
{

	Obfuscatable obfuscator;
	BiMap<Character, ObfuscationRule<Character, Character>> rules;
	String stringToObfuscate;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 *
	 * @throws Exception
	 *             is thrown if an exception occurs
	 */
	@Override
	@BeforeEach
	protected void setUp() throws Exception
	{
		super.setUp();
		// create a rule for obfuscate the key
		rules = SimpleObfuscationTestData.getFirstBiMapObfuscationRules();
	}

	/**
	 * Tear down method will be invoked after every unit test method in this class
	 *
	 * @throws Exception
	 *             is thrown if an exception occurs
	 */
	@Override
	@AfterEach
	protected void tearDown() throws Exception
	{
		super.tearDown();
		obfuscator = null;
		stringToObfuscate = null;
		rules = null;
	}

	/**
	 * Test method for {@link SimpleCharacterObfuscator#disentangle()}
	 */
	@Test
	public void testDisentangle()
	{
		stringToObfuscate = "abac";
		// obfuscate the key
		obfuscator = new SimpleCharacterObfuscator(rules, stringToObfuscate);
		actual = obfuscator.obfuscate();
		expected = "bcbd";
		assertEquals(expected, actual);

		actual = obfuscator.disentangle();
		expected = stringToObfuscate;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link SimpleCharacterObfuscator#obfuscate()}
	 */
	@Test
	public void testObfuscate()
	{
		// a key for obfuscation
		stringToObfuscate = "abac";

		// obfuscate the key
		obfuscator = new SimpleCharacterObfuscator(rules, stringToObfuscate);
		actual = obfuscator.obfuscate();
		expected = "bcbd";
		assertEquals(expected, actual);

		actual = obfuscator.disentangle();
		expected = stringToObfuscate;
		assertEquals(expected, actual);
	}

}
