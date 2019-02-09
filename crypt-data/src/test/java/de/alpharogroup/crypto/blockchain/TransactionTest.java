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
package de.alpharogroup.crypto.blockchain;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.security.PublicKey;

import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.reader.PublicKeyReader;
import de.alpharogroup.evaluate.object.evaluators.SilentEqualsHashCodeAndToStringEvaluator;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link Transaction}
 */
public class TransactionTest
{
	private final static byte[] fixedSignature = new byte[] { 48, 44, 2, 20, 89, 48, -114, -49, 36,
			65, 116, -5, 88, 6, -38, -110, -30, -73, 59, -53, 19, -49, 122, 90, 2, 20, 111, 38, 55,
			-120, -125, 17, -66, -8, -121, 85, 31, -82, -80, -31, -33, 116, 121, -90, 123, -113 };

	Address address;

	@BeforeMethod
	public void setUp() throws Exception
	{

		File publickeyPemDir;
		File publickeyPemFile;
		PublicKey publicKey;

		publickeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		publickeyPemFile = new File(publickeyPemDir, "public.pem");
		publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		address = new Address("foo", publicKey.getEncoded());
	}

	/**
	 * Test method for {@link Transaction} constructors
	 */
	@Test
	public final void testConstructors()
	{
		Transaction object;
		String text;

		object = new Transaction();
		assertNotNull(object);

		text = "transaction-name";
		object = new Transaction(text, address.getHash(), fixedSignature);
		assertNotNull(object.getSignableData());
	}

	/**
	 * Test method for {@link Transaction#equals(Object)} , {@link Transaction#hashCode()} and
	 * {@link Transaction#toString()}
	 */
	@Test(enabled = false)
	public void testEqualsHashcodeAndToStringWithClass()
	{
		boolean expected;
		boolean actual;

		actual = SilentEqualsHashCodeAndToStringEvaluator
			.evaluateEqualsHashcodeAndToStringQuietly(Transaction.class);
		expected = true;
		assertEquals(expected, actual);
	}


	/**
	 * Test method for {@link Transaction} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(Transaction.class);
	}

}
