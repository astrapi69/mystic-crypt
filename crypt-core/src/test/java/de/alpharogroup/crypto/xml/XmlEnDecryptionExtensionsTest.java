package de.alpharogroup.crypto.xml;

import static org.testng.Assert.assertEquals;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;

import org.apache.commons.codec.DecoderException;
import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import com.google.common.collect.BiMap;
import com.thoughtworks.xstream.XStream;

import de.alpharogroup.collections.map.MapFactory;
import de.alpharogroup.collections.pairs.KeyValuePair;
import de.alpharogroup.crypto.obfuscation.character.ObfuscationOperationTestData;
import de.alpharogroup.crypto.obfuscation.rule.ObfuscationOperationRule;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link XmlEnDecryptionExtensions}
 */
public class XmlEnDecryptionExtensionsTest
{
	
	/** The {@link XStream} object */
	XStream xStream;

	/** The aliases for the {@link XStream} object */
	Map<String, Class<?>> aliases;
	{
		xStream = new XStream();
		XStream.setupDefaultSecurity(xStream);
		xStream.allowTypesByWildcard(new String[] { "de.alpharogroup.**" });
		aliases = MapFactory.newLinkedHashMap();
		aliases.put("KeyValuePair", KeyValuePair.class);
		aliases.put("ObfuscationOperationRule", ObfuscationOperationRule.class);
	}

	/**
	 * Test method for
	 * {@link XmlEnDecryptionExtensions#writeToFileAsXmlAndHex(XStream, Map, Object, File)}
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws DecoderException
	 *             is thrown if an odd number or illegal of characters is supplied
	 */
	@Test
	public void testWriteToFileAsXmlAndHex() throws IOException, DecoderException
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> expected;
		BiMap<Character, ObfuscationOperationRule<Character, Character>> actual;
		File xmlFile;
		File xmlDir;

		xmlDir = new File(PathFinder.getSrcTestResourcesDir(), "xml");
		xmlFile = new File(xmlDir, "foo.sor");
		expected = ObfuscationOperationTestData.getFirstBiMapObfuscationOperationRules();
		XmlEnDecryptionExtensions.writeToFileAsXmlAndHex(xStream, aliases, expected, xmlFile);
		actual = XmlEnDecryptionExtensions.readFromFileAsXmlAndHex(xStream, aliases, xmlFile);
		assertEquals(actual, expected);
	}

	/**
	 * Test method for {@link XmlEnDecryptionExtensions#readFromFileAsXmlAndHex(XStream, Map, File)}
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws DecoderException
	 *             is thrown if an odd number or illegal of characters is supplied
	 */
	@Test
	public void testReadFromFileAsXmlAndHex() throws IOException, DecoderException
	{
		BiMap<Character, ObfuscationOperationRule<Character, Character>> expected;
		BiMap<Character, ObfuscationOperationRule<Character, Character>> actual;
		File xmlFile;
		File xmlDir;

		xmlDir = new File(PathFinder.getSrcTestResourcesDir(), "xml");
		xmlFile = new File(xmlDir, "foo.sor");
		expected = ObfuscationOperationTestData.getFirstBiMapObfuscationOperationRules();
		actual = XmlEnDecryptionExtensions.readFromFileAsXmlAndHex(xStream, aliases, xmlFile);
		assertEquals(actual, expected);
	}

	/**
	 * Test method for {@link XmlEnDecryptionExtensions} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		BeanTester beanTester = new BeanTester();
		beanTester.testBean(XmlEnDecryptionExtensions.class);
	}
}
