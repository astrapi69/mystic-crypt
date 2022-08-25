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

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertTrue;

import org.meanbean.test.BeanTester;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.collect.BiMap;

import io.github.astrapi69.AbstractTestCase;
import io.github.astrapi69.crypt.data.obfuscation.rule.ObfuscationRule;
import io.github.astrapi69.mystic.crypt.obfuscation.ObfuscationBiMapTestData;

/**
 * The unit test class for the class {@link SimpleObfuscatorExtensions}
 */
public class SimpleObfuscatorExtensionsTest extends AbstractTestCase<String, String>
{

	Character character;
	Character replaceWith;
	ObfuscationRule<Character, Character> rule;
	BiMap<Character, ObfuscationRule<Character, Character>> rules;
	String stringToDisentangle;
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
	 * Test method for {@link SimpleObfuscatorExtensions#disentangle(BiMap, String)}
	 */
	@Test
	public void testDisentangle()
	{
		// new scenario...
		stringToDisentangle = "d";

		actual = SimpleObfuscatorExtensions.disentangle(rules, stringToDisentangle);
		expected = "c";
		assertEquals(expected, actual);

		// new scenario...

		stringToDisentangle = "bcbd";

		actual = SimpleObfuscatorExtensions.disentangle(rules, stringToDisentangle);
		expected = "abac";
		assertEquals(expected, actual);
		// new scenario...
		stringToDisentangle = "Lfpobsep";

		actual = SimpleObfuscatorExtensions.disentangle(
			SimpleObfuscationTestData.getFirstBiMapObfuscationRules(), stringToDisentangle);
		expected = "Leonardo";
		assertEquals(expected, actual);
		// new scenario...

		stringToDisentangle = "Lpsfn jqtvn epmps tju bnfu, tfb dpotvm wfsufsfn qfsgfdup je. Amjj qspnqub fmfdusbn uf ofd, bu njojnvn dpqjptbf rvp. Ept jvejdp opnjobuj pqpsufsf fj, vtv bu ejdub mfhfoept. Io optusvn jotpmfot ejtqvuboep qsp, jvtup frvjefn jvt je.";

		actual = SimpleObfuscatorExtensions.disentangle(rules, stringToDisentangle);
		expected = "Lorem ipsum dolor sit amet, sea consul verterem perfecto id. Alii prompta electram te nec, at minimum copiosae quo. Eos iudico nominati oportere ei, usu at dicta legendos. In nostrum insolens disputando pro, iusto equidem ius id.";
		assertEquals(expected, actual);

		// new scenario...
		stringToDisentangle = "bcbde";

		actual = SimpleObfuscatorExtensions.disentangle(rules, stringToDisentangle);
		expected = "abacd";
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link SimpleObfuscatorExtensions#disentangleBiMap(BiMap)}
	 */
	@Test(enabled = true)
	public void testDisentangleBiMap()
	{
		BiMap<Character, Character> biMap = ObfuscationBiMapTestData
			.getSmallestBiMapObfuscationRules();
		// new scenario...
		stringToDisentangle = "be";

		actual = SimpleObfuscatorExtensions.disentangleBiMap(biMap, stringToDisentangle);
		expected = "ac";
		assertEquals(expected, actual);

		// new scenario...
		stringToDisentangle = "bcbd";

		actual = SimpleObfuscatorExtensions.disentangleBiMap(
			SimpleObfuscatorExtensions.toCharacterBiMap(rules), stringToDisentangle);
		expected = "abac";
		assertEquals(expected, actual);
		// new scenario...
		stringToDisentangle = "Lfpobsep";

		actual = SimpleObfuscatorExtensions
			.disentangleBiMap(
				SimpleObfuscatorExtensions
					.toCharacterBiMap(SimpleObfuscationTestData.getFirstBiMapObfuscationRules()),
				stringToDisentangle);
		expected = "Leonardo";
		assertEquals(expected, actual);
		// new scenario...

		stringToDisentangle = "Lpsfn jqtvn epmps tju bnfu, tfb dpotvm wfsufsfn qfsgfdup je. Amjj qspnqub fmfdusbn uf ofd, bu njojnvn dpqjptbf rvp. Ept jvejdp opnjobuj pqpsufsf fj, vtv bu ejdub mfhfoept. Io optusvn jotpmfot ejtqvuboep qsp, jvtup frvjefn jvt je.";

		actual = SimpleObfuscatorExtensions.disentangleBiMap(
			SimpleObfuscatorExtensions.toCharacterBiMap(rules), stringToDisentangle);
		expected = "Lorem ipsum dolor sit amet, sea consul verterem perfecto id. Alii prompta electram te nec, at minimum copiosae quo. Eos iudico nominati oportere ei, usu at dicta legendos. In nostrum insolens disputando pro, iusto equidem ius id.";
		assertEquals(expected, actual);

		// new scenario...
		stringToDisentangle = "bcbde";

		actual = SimpleObfuscatorExtensions.disentangleBiMap(
			SimpleObfuscatorExtensions.toCharacterBiMap(rules), stringToDisentangle);
		expected = "abacd";
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link SimpleObfuscatorExtensions#obfuscateWith(BiMap, String)}
	 */
	@Test
	public void testObfuscateWith()
	{
		// new scenario...
		stringToObfuscate = "abac";

		actual = SimpleObfuscatorExtensions.obfuscateWith(rules, stringToObfuscate);
		expected = "bcbd";
		assertEquals(expected, actual);
		// new scenario...
		stringToObfuscate = "abacd";

		actual = SimpleObfuscatorExtensions.obfuscateWith(rules, stringToObfuscate);
		expected = "bcbde";
		assertEquals(expected, actual);
		// new scenario...
		stringToObfuscate = "Lorem ipsum dolor sit amet, sea consul verterem perfecto id. Alii prompta electram te nec, at minimum copiosae quo."
			+ " Eos iudico nominati oportere ei, usu at dicta legendos. In nostrum insolens disputando pro, iusto equidem ius id.";

		actual = SimpleObfuscatorExtensions.obfuscateWith(rules, stringToObfuscate);
		expected = "Lpsfn jqtvn epmps tju bnfu, tfb dpotvm wfsufsfn qfsgfdup je. Amjj qspnqub fmfdusbn uf ofd, bu njojnvn dpqjptbf rvp."
			+ " Ept jvejdp opnjobuj pqpsufsf fj, vtv bu ejdub mfhfoept. Io optusvn jotpmfot ejtqvuboep qsp, jvtup frvjefn jvt je.";
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link SimpleObfuscatorExtensions#toCharacterBiMap(BiMap)}
	 */
	@Test(enabled = true)
	public void testToCharacterBiMap()
	{
		BiMap<Character, Character> actual;
		BiMap<Character, Character> expected;
		BiMap<Character, ObfuscationRule<Character, Character>> obfuscationRules;
		// new scenario...
		obfuscationRules = SimpleObfuscationTestData.getSmallBiMapObfuscationRules();
		actual = SimpleObfuscatorExtensions.toCharacterBiMap(obfuscationRules);
		expected = ObfuscationBiMapTestData.getSmallBiMapRules();
		assertEquals(expected.size(), actual.size());
		assertTrue(actual.equals(expected));
		// new scenario...
		obfuscationRules = SimpleObfuscationTestData.getSmallestBiMapObfuscationRules();
		actual = SimpleObfuscatorExtensions.toCharacterBiMap(obfuscationRules);
		expected = ObfuscationBiMapTestData.getSmallestBiMapObfuscationRules();
		assertEquals(expected.size(), actual.size());
		assertTrue(actual.equals(expected));
		// new scenario...
		obfuscationRules = SimpleObfuscationTestData.getFirstBiMapObfuscationRules();
		actual = SimpleObfuscatorExtensions.toCharacterBiMap(obfuscationRules);
		expected = ObfuscationBiMapTestData.getFirstBiMapObfuscationOperationRules();

		assertEquals(expected.size(), actual.size());
		assertTrue(actual.equals(expected));
	}

	/**
	 * Test method for {@link SimpleObfuscatorExtensions#validate(BiMap)}
	 */
	@Test(enabled = false)
	public void testValidate()
	{
		boolean actual;
		boolean expected;
		BiMap<Character, ObfuscationRule<Character, Character>> biMap;

		biMap = SimpleObfuscationTestData.getFirstBiMapObfuscationRules();
		actual = SimpleObfuscatorExtensions.validate(biMap);
		expected = true;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link SimpleObfuscatorExtensions} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(SimpleObfuscatorExtensions.class);
	}

}
