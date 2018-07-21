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
package de.alpharogroup.crypto.factories;

import static org.testng.Assert.assertNotNull;

import java.lang.reflect.InvocationTargetException;
import java.security.spec.KeySpec;

import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.CryptConst;

/**
 * The class {@link KeySpecFactory}
 */
public class KeySpecFactoryTest
{

	/**
	 * Test method for {@link KeySpecFactory#newPBEKeySpec(String)}
	 */
	@Test
	public void testNewPBEKeySpecString() throws Exception
	{
		KeySpec actual;

		actual = KeySpecFactory.newPBEKeySpec(CryptConst.PRIVATE_KEY);
		assertNotNull(actual);

		actual = KeySpecFactory.newPBEKeySpec(null);
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link KeySpecFactory#newPBEKeySpec(String, byte[], int)}
	 */
	@Test
	public void testNewPBEKeySpecStringByteArrayInt() throws Exception
	{
		KeySpec actual;

		actual = KeySpecFactory.newPBEKeySpec(CryptConst.PRIVATE_KEY, CryptConst.SALT,
			CryptConst.ITERATIONCOUNT);
		assertNotNull(actual);

		actual = KeySpecFactory.newPBEKeySpec(null, CryptConst.SALT,
			CryptConst.ITERATIONCOUNT);
		assertNotNull(actual);
	}

	/**
	 * Test method for {@link KeySpecFactory} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(KeySpecFactory.class);
	}

}
