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
package de.alpharogroup.crypto.key;

import static org.testng.AssertJUnit.assertEquals;

import java.lang.reflect.InvocationTargetException;

import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import de.alpharogroup.collections.array.ArrayExtensions;

/**
 * The unit test class for the class {@link KeyFileFormat}.
 */
public class KeyFileFormatTest
{

	/**
	 * Test method for {@link KeyFileFormat#getFileExtensions()}.
	 */
	@Test
	public void testGetFileExtensions() throws Exception
	{
		String[] expected;
		String[] actual;

		actual = KeyFileFormat.DER.getFileExtensions();

		expected = ArrayExtensions.newArray("der");
		assertEquals(actual, expected);

		actual = KeyFileFormat.PEM.getFileExtensions();

		expected = ArrayExtensions.newArray("cer", "crt", "pem");
		assertEquals(actual, expected);

		actual = KeyFileFormat.P7B.getFileExtensions();

		expected = ArrayExtensions.newArray("p7b", "p7c");
		assertEquals(actual, expected);

	}

	/**
	 * Test method for {@link KeyFileFormat}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(KeyFileFormat.class);
	}

}
