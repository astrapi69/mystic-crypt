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
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.reader.PublicKeyReader;
import de.alpharogroup.evaluate.object.evaluators.SilentEqualsHashCodeAndToStringEvaluator;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link Address}
 */
public class AddressTest
{

	/**
	 * Test method for {@link Address} constructors
	 *
	 * @throws IOException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 */
	@Test
	public final void testConstructors() throws IOException, NoSuchAlgorithmException,
		InvalidKeySpecException, NoSuchProviderException
	{
		Address address;

		address = new Address();
		assertNotNull(address);

		final File publickeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File publickeyPemFile = new File(publickeyPemDir, "public.pem");
		final PublicKey publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		address = new Address("foo", publicKey.getEncoded());
		assertNotNull(address);
	}

	/**
	 * Test method for {@link Address#equals(Object)} , {@link Address#hashCode()} and
	 * {@link Address#toString()}
	 */
	@Test(enabled = false)
	public void testEqualsHashcodeAndToStringWithClass()
	{
		boolean expected;
		boolean actual;

		actual = SilentEqualsHashCodeAndToStringEvaluator
			.evaluateEqualsHashcodeAndToStringQuietly(Address.class);
		expected = true;
		assertEquals(expected, actual);
	}


	/**
	 * Test method for {@link Address} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(Address.class);
	}
}
