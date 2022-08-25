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

import static org.testng.AssertJUnit.assertEquals;

import java.lang.reflect.InvocationTargetException;

import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.collect.BiMap;

import io.github.astrapi69.AbstractTestCase;
import io.github.astrapi69.crypt.api.obfuscation.Obfuscatable;
import io.github.astrapi69.crypt.data.obfuscation.rule.ObfuscationOperationRule;

/**
 * The unit test class for the class {@link CharacterObfuscator}
 */
public class CharacterObfuscatorTest extends AbstractTestCase<String, String>
{

	Obfuscatable obfuscator;
	BiMap<Character, ObfuscationOperationRule<Character, Character>> rules;
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
		rules = ObfuscationOperationTestData.getFirstBiMapObfuscationOperationRules();
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
	 * Test method for {@link CharacterObfuscator#disentangle()}
	 */
	@Test(enabled = true)
	public void testDisentangle()
	{
		stringToObfuscate = "abac";
		// obfuscate the key
		obfuscator = new CharacterObfuscator(rules, stringToObfuscate);
		actual = obfuscator.obfuscate();
		expected = "AcAC";
		assertEquals(expected, actual);

		actual = obfuscator.disentangle();
		expected = stringToObfuscate;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CharacterObfuscator#obfuscate()}
	 */
	@Test(enabled = true)
	public void testObfuscate()
	{
		// a key for obfuscation
		stringToObfuscate = "abac";

		// obfuscate the key
		obfuscator = new CharacterObfuscator(rules, stringToObfuscate);
		actual = obfuscator.obfuscate();
		expected = "AcAC";
		assertEquals(expected, actual);

		actual = obfuscator.disentangle();
		expected = stringToObfuscate;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CharacterObfuscator#obfuscate()}
	 */
	@Test(enabled = true) // TODO inspect and fix...
	public void testObfuscateEightChars()
	{
		// new scenario...
		// a key for obfuscation
		stringToObfuscate = "leonardo";

		// obfuscate the key
		obfuscator = new CharacterObfuscator(rules, stringToObfuscate);
		actual = obfuscator.obfuscate();
		expected = "Lfpobsep";
		assertEquals(expected, actual);

		actual = obfuscator.disentangle();
		expected = stringToObfuscate;
		assertEquals(expected, actual);

		// new scenario...
		// a key for obfuscation
		stringToObfuscate = "leonardo Lorem ipsum dolor sit amet, sea consul verterem perfecto id. Alii prompta electram te nec, at minimum copiosae quo. Eos iudico nominati oportere ei, usu at dicta legendos. In nostrum insolens disputando pro, iusto equidem ius id.";

		// obfuscate the key
		obfuscator = new CharacterObfuscator(rules, stringToObfuscate);
		actual = obfuscator.obfuscate();
		expected = "Lfpobsep Lpsfn jqtvn epmps tju bnfu, tfb dpotvm wfsufsfn qfsgfdup je. Amjj qspnqub fmfdusbn uf ofd, bu njojnvn dpqjptbf rvp. Ept jvejdp opnjobuj pqpsufsf fj, vtv bu ejdub mfhfoept. Io optusvn jotpmfot ejtqvuboep qsp, jvtup frvjefn jvt je.";
		assertEquals(expected, actual);

		actual = obfuscator.disentangle();
		expected = stringToObfuscate;
		assertEquals(expected, actual);

		// new scenario...
		// a key for obfuscation
		stringToObfuscate = "Numbers are only part of the data a typical Java program needs to read and write. Most programs also need to handle text, which is composed of characters. Since computers only really understand numbers, characters are encoded by matching each character in a given script to a particular number. For example, in the common ASCII encoding, the character A is mapped to the number 65; the character B is mapped to the number 66; the character C is mapped to the number 67; and so on. Different encodings may encode different scripts or may encode the same or similar scripts in different ways.";

		// obfuscate the key
		obfuscator = new CharacterObfuscator(rules, stringToObfuscate);
		actual = obfuscator.obfuscate();
		expected = "Nvncfst bsf pomz qbsu pg uif ebub b uzqjdbm Jbwb qsphsbn offet up sfbe boe xsjuf. Mptu qsphsbnt bmtp offe up iboemf ufyu, xijdi jt dpnqptfe pg dibsbdufst. Sjodf dpnqvufst pomz sfbmmz voefstuboe ovncfst, dibsbdufst bsf fodpefe cz nbudijoh fbdi dibsbdufs jo b hjwfo tdsjqu up b qbsujdvmbs ovncfs. Fps fybnqmf, jo uif dpnnpo ASCII fodpejoh, uif dibsbdufs A jt nbqqfe up uif ovncfs 65; uif dibsbdufs B jt nbqqfe up uif ovncfs 66; uif dibsbdufs C jt nbqqfe up uif ovncfs 67; boe tp po. Djggfsfou fodpejoht nbz fodpef ejggfsfou tdsjqut ps nbz fodpef uif tbnf ps tjnjmbs tdsjqut jo ejggfsfou xbzt.";
		assertEquals(expected, actual);

		actual = obfuscator.disentangle();
		expected = "numbers are only part of the data a typical Java program needs to read and write. Most programs also need to handle text, which is composed of characters. Since computers only really understand numbers, characters are encoded by matching each character in a given script to a particular number. For example, in the common ASCII encoding, the character A is mapped to the number 65; the character B is mapped to the number 66; the character C is mapped to the number 67; and so on. Different encodings may encode different scripts or may encode the same or similar scripts in different ways.";
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CharacterObfuscator} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(CharacterObfuscator.class);
	}

}
