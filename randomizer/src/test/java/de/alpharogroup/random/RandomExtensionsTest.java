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
package de.alpharogroup.random;

import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.testng.AssertJUnit;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.BaseTestCase;
import de.alpharogroup.test.objects.Gender;

/**
 * Test class for the class {@link RandomExtensions}.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public class RandomExtensionsTest extends BaseTestCase
{

	/**
	 * {@inheritDoc}
	 */
	@Override
	@BeforeMethod
	protected void setUp() throws Exception
	{
		super.setUp();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	@AfterMethod
	protected void tearDown() throws Exception
	{
		super.tearDown();
	}

	/**
	 * Test method for {@link RandomExtensions#getRandomEntry(java.util.List)} .
	 */
	@Test
	public void testGetRandomEntryList()
	{
		final List<String> list = new ArrayList<>();
		list.add("Anton");
		list.add("Kosta");
		list.add("Caesar");
		list.add("Asterios");
		list.add("Anastasia");
		list.add("Katerina");
		for (int i = 0; i < 100; i++)
		{
			final String randomEntry = RandomExtensions.getRandomEntry(list);
			this.result = list.contains(randomEntry);
			AssertJUnit.assertTrue("", this.result);
		}
	}

	/**
	 * Test method for {@link RandomExtensions#getRandomEntry(java.util.Map)} .
	 */
	@Test
	public void testGetRandomEntryMap()
	{
		final Map<String, String> map = new HashMap<>();
		map.put("1", "novalue");
		map.put("2", "somevalue");
		map.put("3", "othervalue");
		map.put("4", "value");
		map.put("5", "value");
		final Collection<String> values = map.values();
		for (int i = 0; i < 100; i++)
		{
			final String randomValue = (String)RandomExtensions.getRandomEntry(map);
			this.result = values.contains(randomValue);
			AssertJUnit.assertTrue("", this.result);
		}
	}

	@Test
	public void testGetRandomEnum()
	{
		final Gender[] genders = Gender.values();
		Gender randomEnumEntry = RandomExtensions.getRandomEnum(genders);
		System.out.println(randomEnumEntry.name());

		randomEnumEntry = RandomExtensions.getRandomEnum(randomEnumEntry);
		System.out.println(randomEnumEntry.name());

		randomEnumEntry = RandomExtensions.getRandomEnum(Gender.class);
		System.out.println(randomEnumEntry.name());
	}

	/**
	 * Test method for {@link RandomExtensions#getRandomFloat(int, int)} .
	 */
	@Test
	public void testGetRandomFloat()
	{
		final int beforeComma = 2;
		final int afterComma = 4;
		for (int i = 0; i < 100; i++)
		{
			final float randomFloat = RandomExtensions.getRandomFloat(afterComma, beforeComma);
			this.result = 0 < randomFloat;
			AssertJUnit.assertTrue("", this.result);
		}
	}

	/**
	 * Test method for {@link RandomExtensions#getRandomKey(java.util.Map)} .
	 */
	@Test
	public void testGetRandomKey()
	{
		final Map<String, String> map = new HashMap<>();
		map.put("1", "novalue");
		map.put("2", "somevalue");
		map.put("3", "othervalue");
		map.put("4", "value");
		map.put("5", "value");
		final Set<String> keys = map.keySet();
		for (int i = 0; i < 100; i++)
		{
			final String randomKey = (String)RandomExtensions.getRandomKey(map);
			this.result = keys.contains(randomKey);
			AssertJUnit.assertTrue("", this.result);
		}
	}

	/**
	 * Test method for {@link RandomExtensions#randomBoolean()}.
	 */
	@Test
	public void testRandomBoolean()
	{
	}

	@Test
	public void testRandomByteArray()
	{
		final byte[] randomByteArray = RandomExtensions.randomByteArray(8);
		System.out.println(new String(randomByteArray, Charset.forName("UTF-8")));
	}

	/**
	 * Test method for {@link RandomExtensions#randomChar(java.lang.String)} .
	 */
	@Test
	public void testRandomChar()
	{
		final String string = Constants.LOWCASECHARS;
		for (int i = 0; i < 100; i++)
		{
			final char randomChar = RandomExtensions.randomChar(string);
			final CharBuffer charBuffer = CharBuffer.allocate(1);
			charBuffer.put(randomChar);
			this.result = string.contains(charBuffer);
			AssertJUnit.assertTrue("", this.result);
		}
	}

	/**
	 * Test method for {@link RandomExtensions#randomInt(int)}.
	 */
	@Test
	public void testRandomInt()
	{
		System.out.println("Generate 100 secure random numbers:");
		for (int i = 0; i < 100; i++)
		{
			final int randomInt = RandomExtensions.randomInt(5);
			System.out.println(randomInt);
		}
	}

	/**
	 * Test method for {@link RandomExtensions#getRandomString(java.lang.String[])} .
	 */
	@Test
	public void testRandomStringStringArray()
	{
		final String[] array = { "blab", "flih", "klap", "teta", "brut", "gzft", "ccp" };
		final List<String> listFromArray = Arrays.asList(array);
		for (int i = 0; i < 100; i++)
		{
			final String randomString = RandomExtensions.getRandomString(array);
			this.result = listFromArray.contains(randomString);
			AssertJUnit.assertTrue("", this.result);
		}
	}

	/**
	 * Test method for {@link RandomExtensions#getRandomString(java.lang.String, int)} .
	 */
	@Test
	public void testRandomStringStringInt()
	{
		final CharBuffer charBuffer = CharBuffer.allocate(45);
		final int length = 5;
		final String chars = Constants.LCCHARSWNASC;
		charBuffer.put(chars);
		for (int i = 0; i < 100; i++)
		{
			final String randomString = RandomExtensions.getRandomString(chars, length);
			this.result = randomString.contains(charBuffer);
			AssertJUnit.assertTrue("", this.result);
		}
	}

	/**
	 * Test method for {@link RandomExtensions#randomToken()} .
	 */
	@Test
	public void testRandomToken()
	{
		final String randomToken = RandomExtensions.randomToken();
		AssertJUnit.assertNotNull(randomToken);
		AssertJUnit.assertTrue(randomToken.length() == 26);
	}

}
