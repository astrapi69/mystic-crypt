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
package de.alpharogroup.crypto.hash;

import java.lang.reflect.InvocationTargetException;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.HashAlgorithm;

/**
 * The unit test class for the class {@link HashExtensions}.
 */
public class HashExtensionsTest
{

	/**
	 * Test method for {@link HashExtensions#hash(String, String, HashAlgorithm, Charset)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails.
	 */
	@Test
	public void testHash() throws NoSuchAlgorithmException
	{
		final Charset charset = Charset.forName("UTF-8");
		final String password = "abcdefghijklmnopqrst";
		final String newInsertPassword = "abcdefghijklmnopqrst";
		final String salt = "NzeCdmaz";
		final HashAlgorithm hashAlgorithm = HashAlgorithm.SHA_512;
		final String expected = HashExtensions.hash(password, salt, hashAlgorithm, charset);
		final String actual = HashExtensions.hash(newInsertPassword, salt, hashAlgorithm, charset);

		AssertJUnit.assertTrue("'expected' should be equal with 'actual'.",
			expected.equals(actual));
	}

	/**
	 * Test method for {@link HashExtensions#hashAndBase64(String, String, HashAlgorithm, Charset)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails.
	 */
	@Test
	public void testHashAndBase64() throws NoSuchAlgorithmException
	{
		final Charset charset = Charset.forName("UTF-8");
		final String password = "secret";
		final String newInsertPassword = "secret";
		final String salt = "NzeCdmaz";
		final HashAlgorithm hashAlgorithm = HashAlgorithm.SHA_512;
		final String expected = HashExtensions.hashAndBase64(password, salt, hashAlgorithm,
			charset);
		final String actual = HashExtensions.hashAndBase64(newInsertPassword, salt, hashAlgorithm,
			charset);
		AssertJUnit.assertTrue("'expected' should be equal with 'actual'.",
			expected.equals(actual));
	}


	/**
	 * Test method for {@link HashExtensions#hash(byte[], String, HashAlgorithm, Charset)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails.
	 */
	@Test
	public void testHashByteArray() throws NoSuchAlgorithmException
	{
		final Charset charset = Charset.forName("UTF-8");
		final String password = "abcdefghijklmnopqrst";
		final String newInsertPassword = "abcdefghijklmnopqrst";
		final String salt = "NzeCdmaz";
		final HashAlgorithm hashAlgorithm = HashAlgorithm.SHA_512;
		byte[] expected = HashExtensions.hash(password.getBytes(), salt, hashAlgorithm, charset);
		byte[] actual = HashExtensions.hash(newInsertPassword.getBytes(), salt, hashAlgorithm,
			charset);

		AssertJUnit.assertTrue(expected.length == actual.length);
		AssertJUnit.assertTrue("'expected' should be equal with 'actual'.",
			Arrays.equals(expected, actual));

		expected = HashExtensions.hash(password.getBytes(), null, hashAlgorithm, charset);
		actual = HashExtensions.hash(newInsertPassword.getBytes(), null, hashAlgorithm, charset);

		AssertJUnit.assertTrue(expected.length == actual.length);
		AssertJUnit.assertTrue("'expected' should be equal with 'actual'.",
			Arrays.equals(expected, actual));
	}

	/**
	 * Test method for {@link HashExtensions#hash(byte[], HashAlgorithm)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails.
	 */
	@Test
	public void testHashByteArrayWithAlgorithm() throws NoSuchAlgorithmException
	{
		final String password = "abcdefghijklmnopqrst";
		final String newInsertPassword = "abcdefghijklmnopqrst";
		final HashAlgorithm hashAlgorithm = HashAlgorithm.SHA_512;
		byte[] expected = HashExtensions.hash(password.getBytes(), hashAlgorithm);
		byte[] actual = HashExtensions.hash(newInsertPassword.getBytes(), hashAlgorithm);

		AssertJUnit.assertTrue(expected.length == actual.length);
		AssertJUnit.assertTrue("'expected' should be equal with 'actual'.",
			Arrays.equals(expected, actual));
	}
	
	/**
	 * Test method for {@link HashExtensions} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(HashExtensions.class);
	}

}
