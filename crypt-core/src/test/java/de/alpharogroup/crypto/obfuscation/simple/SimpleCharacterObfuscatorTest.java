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
package de.alpharogroup.crypto.obfuscation.simple;

import static org.testng.AssertJUnit.assertEquals;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.collect.BiMap;

import de.alpharogroup.AbstractTestCase;
import de.alpharogroup.crypto.obfuscation.api.Obfuscatable;
import de.alpharogroup.crypto.obfuscation.rule.ObfuscationRule;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;

/**
 * The unit test class for the class {@link SimpleCharacterObfuscator}
 */
@FieldDefaults(level = AccessLevel.PRIVATE)
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
	@BeforeMethod
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
	@AfterMethod
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
	@Test(enabled = true)
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
	@Test(enabled = true)
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
