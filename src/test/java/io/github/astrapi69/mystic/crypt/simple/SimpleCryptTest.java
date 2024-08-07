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
package io.github.astrapi69.mystic.crypt.simple;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

/**
 * The unit test class for the class {@link SimpleCrypt}
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class SimpleCryptTest
{

	/**
	 * Test method for test the method {@link SimpleCrypt#oneTimePadCrypt(byte[], byte[])}
	 */
	@Test
	public void testOneTimePad()
	{
		byte[] encoded;
		byte[] decoded;
		byte[] secret = "top-secret".getBytes();
		byte[] key = new byte[secret.length];

		encoded = SimpleCrypt.oneTimePadCrypt(key, secret);
		decoded = SimpleCrypt.oneTimePadCrypt(key, encoded);

		assertTrue(Arrays.equals(secret, decoded));
	}

	/**
	 * Test method for test the method {@link SimpleCrypt#encode(String)} and
	 * {@link SimpleCrypt#decode(String)}
	 */
	@Test
	public void testSimpleCrypt01()
	{
		String actual;
		String expected;
		String testString;
		String encrypted;

		testString = "top secret";
		expected = testString;
		encrypted = SimpleCrypt.encode(testString);
		actual = SimpleCrypt.decode(encrypted);
		assertEquals(actual, expected);
	}

	/**
	 * Test method for test the method {@link SimpleCrypt#encode(String)} and
	 * {@link SimpleCrypt#decode(String)}
	 */
	@Test
	public void testSimpleCrypt02()
	{
		String actual;
		String expected;
		String encrypted;
		String testString;
		int verschiebe;

		testString = "top secret";
		verschiebe = 4;

		expected = new StringBuffer(testString).toString().trim();
		encrypted = SimpleCrypt.encode(testString, verschiebe);
		actual = SimpleCrypt.decode(encrypted, verschiebe);
		assertEquals(actual, expected);
	}

	/**
	 * Test method for {@link SimpleCrypt} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		BeanTester beanTester = new BeanTester();
		beanTester.testBean(SimpleCrypt.class);
	}

}
