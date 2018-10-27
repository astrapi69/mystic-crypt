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

import de.alpharogroup.AbstractTestCase;
import de.alpharogroup.crypto.obfuscation.ObfuscationTestData;
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
	String stringToDisentangle;
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
		rules = ObfuscationTestData.getSmallBiMapObfuscationOperationRules();
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#disentangle(BiMap, String)}
	 */
	@Test
	public void testDisentangle()
	{
		// new scenario...
		stringToDisentangle = "d";

		actual = ObfuscatorExtensions.disentangle(rules, stringToDisentangle);
		expected = "d";
		assertEquals(expected, actual);

		// new scenario...
		stringToDisentangle = "AcACd";

		actual = ObfuscatorExtensions.disentangle(rules, stringToDisentangle);
		expected = "abacd";
		assertEquals(expected, actual);
		// new scenario...
		stringToDisentangle = "Lfpobsep";

		actual = ObfuscatorExtensions.disentangle(
			ObfuscationTestData.getFirstBiMapObfuscationOperationRules(), stringToDisentangle);
		expected = "leonardo";
		assertEquals(expected, actual);
		// new scenario...
		stringToDisentangle = "Lfpobsep Lpsfn jqtvn epmps tju bnfu, tfb dpotvm wfsufsfn qfsgfdup je. Amjj qspnqub fmfdusbn uf ofd, bu njojnvn dpqjptbf rvp. Ept jvejdp opnjobuj pqpsufsf fj, vtv bu ejdub mfhfoept. Io optusvn jotpmfot ejtqvuboep qsp, jvtup frvjefn jvt je.";

		actual = ObfuscatorExtensions.disentangle(
			ObfuscationTestData.getFirstBiMapObfuscationOperationRules(), stringToDisentangle);
		expected = "leonardo Lorem ipsum dolor sit amet, sea consul verterem perfecto id. Alii prompta electram te nec, at minimum copiosae quo. Eos iudico nominati oportere ei, usu at dicta legendos. In nostrum insolens disputando pro, iusto equidem ius id.";
		assertEquals(expected, actual);

		// new scenario...
		stringToDisentangle = "AcACd";

		actual = ObfuscatorExtensions.disentangle(rules, stringToDisentangle);
		expected = "abacd";
		assertEquals(expected, actual);
		// new scenario...
		stringToDisentangle = "Lfpobsep";
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
	 * Test method for {@link ObfuscatorExtensions#validate(BiMap)}
	 */
	@Test
	public void testValidate()
	{
		boolean actual;
		boolean expected;
		BiMap<Character,ObfuscationOperationRule<Character,Character>> biMap;
		
		biMap = ObfuscationTestData.getFirstBiMapObfuscationOperationRules();
		actual = ObfuscatorExtensions.validate(biMap);
		expected = true;
		assertEquals(expected, actual);
		
		biMap = ObfuscationTestData.getSmallBiMapObfuscationOperationRules();
		actual = ObfuscatorExtensions.validate(biMap);
		expected = true;
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
