/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto.obfuscation.rule;

import static org.testng.AssertJUnit.assertEquals;

import java.lang.reflect.InvocationTargetException;

import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

/**
 * The unit test class for the class {@link Operation}
 */
public class OperationTest
{

	/**
	 * Test method for {@link Operation#operate(char, Operation)}
	 */
	@Test
	public void testOperateCharOperation() throws Exception
	{
		Character expected;
		Character actual;

		actual = Operation.operate('a', Operation.UPPERCASE);
		expected = 'A';
		assertEquals(expected, actual);

		actual = Operation.operate('a', Operation.TITLECASE);
		expected = 'A';
		assertEquals(expected, actual);

		actual = Operation.operate('A', Operation.LOWERCASE);
		expected = 'a';
		assertEquals(expected, actual);

		actual = Operation.operate('A', Operation.NEGATECASE);
		expected = 'a';
		assertEquals(expected, actual);

		actual = Operation.operate('a', Operation.NEGATECASE);
		expected = 'A';
		assertEquals(expected, actual);

		actual = Operation.operate('A', null);
		expected = 'A';
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link Operation#operate(char, Operation, boolean)}
	 */
	@Test
	public void testOperateCharOperationBoolean() throws Exception
	{
		Character expected;
		Character actual;

		actual = Operation.operate('a', Operation.UPPERCASE, false);
		expected = 'A';
		assertEquals(expected, actual);

		actual = Operation.operate('a', Operation.TITLECASE, false);
		expected = 'A';
		assertEquals(expected, actual);

		actual = Operation.operate('A', Operation.LOWERCASE, false);
		expected = 'a';
		assertEquals(expected, actual);

		actual = Operation.operate('A', Operation.NEGATECASE, false);
		expected = 'a';
		assertEquals(expected, actual);

		actual = Operation.operate('a', Operation.UPPERCASE, true);
		expected = 'a';
		assertEquals(expected, actual);

		actual = Operation.operate('a', Operation.TITLECASE, true);
		expected = 'A';
		assertEquals(expected, actual);

		actual = Operation.operate('A', Operation.LOWERCASE, true);
		expected = 'A';
		assertEquals(expected, actual);

		actual = Operation.operate('A', Operation.TITLECASE, true);
		expected = 'a';
		assertEquals(expected, actual);
		// double negation does nothing to character
		actual = Operation.operate('A', Operation.NEGATECASE, true);
		expected = 'A';
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link Operation}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(Operation.class);
	}

}
