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
package de.alpharogroup.crypto.xml;

import static org.testng.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.util.Map;

import de.alpharogroup.crypto.file.xml.XmlDecryptionExtensions;
import org.apache.commons.codec.DecoderException;
import org.junit.Test;
import org.testng.annotations.BeforeMethod;

import com.google.common.collect.BiMap;
import com.thoughtworks.xstream.XStream;

import de.alpharogroup.collections.map.MapFactory;
import de.alpharogroup.collections.pairs.KeyValuePair;
import de.alpharogroup.crypto.obfuscation.character.ObfuscationOperationTestData;
import de.alpharogroup.crypto.obfuscation.rule.ObfuscationOperationRule;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link XmlDecryptionExtensions}
 */
public class XmlDecryptionExtensionsTest
{

	/** The aliases for the {@link XStream} object */
	Map<String, Class<?>> aliases;
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

	BiMap<Character, ObfuscationOperationRule<Character, Character>> expected;
	BiMap<Character, ObfuscationOperationRule<Character, Character>> actual;
	File xmlFile;
	File xmlDir;



	@BeforeMethod
	protected void setUp()
	{
		xmlDir = new File(PathFinder.getSrcTestResourcesDir(), "xml");
		xmlFile = new File(xmlDir, "foo.sor");
	}

	/**
	 * Test method for {@link XmlDecryptionExtensions#readFromFileAsXmlAndHex(XStream, Map, File)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws DecoderException
	 *             is thrown if an odd number or illegal of characters is supplied
	 */
	@Test
	public void testReadFromFileAsXmlAndHex() throws IOException, DecoderException
	{
		expected = ObfuscationOperationTestData.getFirstBiMapObfuscationOperationRules();
		actual = XmlDecryptionExtensions.readFromFileAsXmlAndHex(xStream, aliases, xmlFile);
		assertEquals(actual, expected);
	}

}
