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
package de.alpharogroup.crypto.obfuscation.character;

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.apache.commons.codec.DecoderException;
import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;
import com.thoughtworks.xstream.XStream;

import de.alpharogroup.AbstractTestCase;
import de.alpharogroup.collections.map.MapFactory;
import de.alpharogroup.collections.pairs.KeyValuePair;
import de.alpharogroup.collections.set.SetFactory;
import de.alpharogroup.crypto.file.xml.XmlDecryptionExtensions;
import de.alpharogroup.crypto.obfuscation.rule.CharacterObfuscationOperationRule;
import de.alpharogroup.crypto.obfuscation.rule.ObfuscationOperationRule;
import de.alpharogroup.crypto.obfuscation.rule.Operation;
import de.alpharogroup.file.search.PathFinder;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;

/**
 * The unit test class for the class {@link ObfuscatorExtensions}
 */
@FieldDefaults(level = AccessLevel.PRIVATE)
public class ObfuscatorExtensionsTest extends AbstractTestCase<String, String>
{

	/** The aliases for the {@link XStream} object */
	Map<String, Class<?>> aliases;
	List<KeyValuePair<Character, ObfuscationOperationRule<Character, Character>>> data;
	BiMap<Character, ObfuscationOperationRule<Character, Character>> fullSizeRules;
	BiMap<Character, ObfuscationOperationRule<Character, Character>> smallSizeRules;
	String stringToDisentangle;
	String stringToObfuscate;

	BiMap<Character, ObfuscationOperationRule<Character, Character>> testRules;
	/** The {@link XStream} object */
	XStream xStream;
	{
		xStream = new XStream();
		XStream.setupDefaultSecurity(xStream);
		xStream.allowTypesByWildcard(new String[] { "de.alpharogroup.**" });
		aliases = MapFactory.newLinkedHashMap();
		aliases.put("KeyValuePair", KeyValuePair.class);
		aliases.put("ObfuscationOperationRule", ObfuscationOperationRule.class);
	}

	File xmlFile;
	File xmlListFile;
	File xmlDir;

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

		xmlDir = new File(PathFinder.getSrcTestResourcesDir(), "xml");
		xmlFile = new File(xmlDir, "small-size-operation-rules.oor");

		smallSizeRules = XmlDecryptionExtensions.readFromFileAsXmlAndHex(xStream, aliases, xmlFile);

		xmlFile = new File(xmlDir, "full-size-operation-rules.oor");
		fullSizeRules = XmlDecryptionExtensions.readFromFileAsXmlAndHex(xStream, aliases, xmlFile);

		xmlListFile = new File(xmlDir, "pwhex-foo.oor");
		data = XmlDecryptionExtensions.readFromFileAsXmlAndHex(xStream, aliases, xmlListFile);
		testRules = loadXmlListToBiMap(xmlListFile);

	}

	BiMap<Character, ObfuscationOperationRule<Character, Character>> loadXmlListToBiMap(
		File xmlListFile) throws IOException, DecoderException
	{
		List<KeyValuePair<Character, ObfuscationOperationRule<Character, Character>>> data = XmlDecryptionExtensions
			.readFromFileAsXmlAndHex(xStream, aliases, xmlListFile);
		BiMap<Character, ObfuscationOperationRule<Character, Character>> rules = HashBiMap
			.create(KeyValuePair.toMap(data));
		return rules;
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#disentangle(BiMap, String)}
	 */
	@Test
	public void testDisentangle()
	{
		// new scenario...
		stringToDisentangle = "d";

		actual = ObfuscatorExtensions.disentangle(smallSizeRules, stringToDisentangle);
		expected = "d";
		assertEquals(expected, actual);

		// new scenario...
		stringToDisentangle = "AcACd";

		actual = ObfuscatorExtensions.disentangle(smallSizeRules, stringToDisentangle);
		expected = "abacd";
		assertEquals(expected, actual);
		// new scenario...
		stringToDisentangle = "Lfpobsep";

		actual = ObfuscatorExtensions.disentangle(fullSizeRules, stringToDisentangle);
		expected = "leonardo";
		assertEquals(expected, actual);
		// new scenario...
		stringToDisentangle = "Lfpobsep Lpsfn jqtvn epmps tju bnfu, tfb dpotvm wfsufsfn qfsgfdup je. Amjj qspnqub fmfdusbn uf ofd, bu njojnvn dpqjptbf rvp. Ept jvejdp opnjobuj pqpsufsf fj, vtv bu ejdub mfhfoept. Io optusvn jotpmfot ejtqvuboep qsp, jvtup frvjefn jvt je.";

		actual = ObfuscatorExtensions.disentangle(fullSizeRules, stringToDisentangle);
		expected = "leonardo Lorem ipsum dolor sit amet, sea consul verterem perfecto id. Alii prompta electram te nec, at minimum copiosae quo. Eos iudico nominati oportere ei, usu at dicta legendos. In nostrum insolens disputando pro, iusto equidem ius id.";
		assertEquals(expected, actual);

		// new scenario...
		stringToDisentangle = "AcACd";

		actual = ObfuscatorExtensions.disentangle(smallSizeRules, stringToDisentangle);
		expected = "abacd";
		assertEquals(expected, actual);
		// new scenario...
		stringToDisentangle = "Lfpobsep";
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#disentangle(BiMap, String)}
	 *
	 * @throws DecoderException
	 * @throws IOException
	 */
	@Test
	public void testDisentangleImprovedWithTestRules() throws IOException, DecoderException
	{

		String obfuscateWith;
		// new scenario...
		stringToDisentangle = "Ast3r70s";

		actual = ObfuscatorExtensions.disentangleImproved(testRules, stringToDisentangle);
		expected = "asterios";
		assertEquals(expected, actual);

		// new scenario...
		stringToObfuscate = "Asterios";

		testRules = loadXmlListToBiMap(xmlListFile);
		testRules.put(Character.valueOf('A'), ObfuscationOperationRule
			.<Character, Character> builder().character('A').replaceWith('5').build());
		obfuscateWith = ObfuscatorExtensions.obfuscateWith(testRules, stringToObfuscate);

		actual = ObfuscatorExtensions.disentangleImproved(testRules, obfuscateWith);
		expected = stringToObfuscate;
		assertEquals(expected, actual);

	}

	@Test
	public void testInverse()
	{
		Character character;
		Set<Integer> indexes;
		boolean inverted;
		Operation operation;
		Character replaceWith;
		CharacterObfuscationOperationRule rule;
		Character actual;
		Character expected;
		Optional<Character> operatedCharacter;

		inverted = false;
		operatedCharacter = Optional.empty();
		character = Character.valueOf('a');
		replaceWith = 'b';
		operation = Operation.UPPERCASE;
		indexes = SetFactory.newHashSet(0, 2);

		rule = new CharacterObfuscationOperationRule(character, indexes, inverted,
			operatedCharacter, operation, replaceWith);

		ObfuscatorExtensions.inverse(rule);

		actual = rule.getCharacter();
		expected = replaceWith;
		assertEquals(actual, expected);

		actual = rule.getReplaceWith();
		expected = character;
		assertEquals(actual, expected);
	}

	/**
	 * Test method for {@link ObfuscatorExtensions#disentangle(BiMap, String)}
	 */
	@Test
	public void testDisentangleWithTestRules()
	{
		String obfuscateWith;
		// new scenario...
		stringToObfuscate = "asterios";
		obfuscateWith = ObfuscatorExtensions.obfuscateWith(testRules, stringToObfuscate);

		actual = ObfuscatorExtensions.disentangle(data, obfuscateWith);
		expected = stringToObfuscate;
		assertEquals(expected, actual);

		// new scenario...
		stringToObfuscate = "Leonardo!";
		obfuscateWith = ObfuscatorExtensions.obfuscateWith(testRules, stringToObfuscate);

		actual = ObfuscatorExtensions.disentangle(data, obfuscateWith);
		expected = stringToObfuscate;
		assertEquals(expected, actual);

	}

	/**
	 * Test method for {@link ObfuscatorExtensions#obfuscateWith(BiMap, String)}
	 */
	@Test
	public void testObfuscateWith()
	{
		// new scenario...
		stringToObfuscate = "abac";

		actual = ObfuscatorExtensions.obfuscateWith(smallSizeRules, stringToObfuscate);
		expected = "AcAC";
		assertEquals(expected, actual);
		// new scenario...
		stringToObfuscate = "abacd";

		actual = ObfuscatorExtensions.obfuscateWith(smallSizeRules, stringToObfuscate);
		expected = "AcACd";
		assertEquals(expected, actual);

		// new scenario...
		stringToObfuscate = "asterios";
		actual = ObfuscatorExtensions.obfuscateWith(testRules, stringToObfuscate);
		expected = "Ast3r70s";
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

		actual = ObfuscatorExtensions.validate(fullSizeRules);
		expected = true;
		assertEquals(expected, actual);

		actual = ObfuscatorExtensions.validate(smallSizeRules);
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
