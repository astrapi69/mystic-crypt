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
package de.alpharogroup.crypto.simple;

import java.lang.reflect.InvocationTargetException;

import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

/**
 * The unit test class for the class {@link SimpleCrypt}
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class SimpleCryptTest
{

	/**
	 * Test method for test the method {@link SimpleCrypt#encode(String)} and
	 * {@link SimpleCrypt#decode(String)}.
	 */
	@Test
	public void testSimpleCrypt()
	{
		final String testString = "top secret";
		final String expected = testString;
		final String encrypted = SimpleCrypt.encode(testString);
		final String decrypted = SimpleCrypt.decode(encrypted);
		AssertJUnit.assertTrue(decrypted.equals(expected));
		testSimpleCrypt(testString, 4);
	}

	/**
	 * Test method for test the method {@link SimpleCrypt#encode(String)} and
	 * {@link SimpleCrypt#decode(String)}.
	 *
	 * @param testString
	 *            the test string
	 * @param verschiebe
	 *            the relocate
	 */
	protected void testSimpleCrypt(final String testString, final int verschiebe)
	{
		final String expected = new StringBuffer(testString).toString().trim();
		final String encrypted = SimpleCrypt.encode(testString, verschiebe);
		final String decrypted = SimpleCrypt.decode(encrypted, verschiebe);
		AssertJUnit.assertTrue(decrypted.equals(expected));
	}

	/**
	 * Test method for {@link SimpleCrypt} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(SimpleCrypt.class);
	}


}
