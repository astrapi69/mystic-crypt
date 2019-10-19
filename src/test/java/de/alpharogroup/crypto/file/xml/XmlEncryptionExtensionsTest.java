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
package de.alpharogroup.crypto.file.xml;

import static org.testng.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;

import org.apache.commons.codec.DecoderException;
import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.collect.BiMap;
import com.thoughtworks.xstream.XStream;

import de.alpharogroup.collections.map.MapFactory;
import de.alpharogroup.collections.pairs.KeyValuePair;
import de.alpharogroup.crypto.obfuscation.character.ObfuscationOperationTestData;
import de.alpharogroup.crypto.obfuscation.rule.ObfuscationOperationRule;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link XmlEncryptionExtensions}
 */
public class XmlEncryptionExtensionsTest
{

	BiMap<Character, ObfuscationOperationRule<Character, Character>> actual;
	/** The aliases for the {@link XStream} object */
	Map<String, Class<?>> aliases;
	BiMap<Character, ObfuscationOperationRule<Character, Character>> expected;

	File xmlDir;
	File xmlFile;
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

	@BeforeMethod
	protected void setUp()
	{
		xmlDir = new File(PathFinder.getSrcTestResourcesDir(), "xml");
		xmlFile = new File(xmlDir, "foo.sor");
	}

	/**
	 * Test method for {@link XmlEncryptionExtensions} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		BeanTester beanTester = new BeanTester();
		beanTester.testBean(XmlEncryptionExtensions.class);
	}

	/**
	 * Test method for
	 * {@link XmlEncryptionExtensions#writeToFileAsXmlAndHex(XStream, Map, Object, File)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws DecoderException
	 *             is thrown if an odd number or illegal of characters is supplied
	 */
	@Test
	public void testWriteToFileAsXmlAndHex() throws IOException, DecoderException
	{
		expected = ObfuscationOperationTestData.getFirstBiMapObfuscationOperationRules();
		XmlEncryptionExtensions.writeToFileAsXmlAndHex(xStream, aliases, expected, xmlFile);
		actual = XmlDecryptionExtensions.readFromFileAsXmlAndHex(xStream, aliases, xmlFile);
		assertEquals(actual, expected);
	}

}
