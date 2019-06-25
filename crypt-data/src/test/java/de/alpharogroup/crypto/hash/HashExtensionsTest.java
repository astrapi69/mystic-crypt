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
package de.alpharogroup.crypto.hash;

import static org.testng.AssertJUnit.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.HashAlgorithm;

/**
 * The unit test class for the class {@link HashExtensions}
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
		String actual;
		String expected;
		Charset charset;
		String password;
		String newInsertPassword;
		String salt;
		HashAlgorithm hashAlgorithm;

		charset = Charset.forName("UTF-8");
		password = "abcdefghijklmnopqrst";
		newInsertPassword = "abcdefghijklmnopqrst";
		salt = "NzeCdmaz";
		hashAlgorithm = HashAlgorithm.SHA_512;
		expected = HashExtensions.hash(password, salt, hashAlgorithm, charset);
		actual = HashExtensions.hash(newInsertPassword, salt, hashAlgorithm, charset);

		assertTrue("'expected' should be equal with 'actual'.", expected.equals(actual));
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
		String actual;
		String expected;
		Charset charset;
		String password;
		String newInsertPassword;
		String salt;
		HashAlgorithm hashAlgorithm;

		charset = Charset.forName("UTF-8");
		password = "secret";
		newInsertPassword = "secret";
		salt = "NzeCdmaz";
		hashAlgorithm = HashAlgorithm.SHA_512;
		expected = HashExtensions.hashAndBase64(password, salt, hashAlgorithm, charset);
		actual = HashExtensions.hashAndBase64(newInsertPassword, salt, hashAlgorithm, charset);
		assertTrue("'expected' should be equal with 'actual'.", expected.equals(actual));
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
		byte[] actual;
		byte[] expected;
		Charset charset;
		String password;
		String newInsertPassword;
		String salt;
		HashAlgorithm hashAlgorithm;

		charset = Charset.forName("UTF-8");
		password = "abcdefghijklmnopqrst";
		newInsertPassword = "abcdefghijklmnopqrst";
		salt = "NzeCdmaz";
		hashAlgorithm = HashAlgorithm.SHA_512;
		expected = HashExtensions.hash(password.getBytes(), salt, hashAlgorithm, charset);
		actual = HashExtensions.hash(newInsertPassword.getBytes(), salt, hashAlgorithm, charset);

		assertTrue(expected.length == actual.length);
		assertTrue("'expected' should be equal with 'actual'.", Arrays.equals(expected, actual));

		expected = HashExtensions.hash(password.getBytes(), null, hashAlgorithm, charset);
		actual = HashExtensions.hash(newInsertPassword.getBytes(), null, hashAlgorithm, charset);

		assertTrue(expected.length == actual.length);
		assertTrue("'expected' should be equal with 'actual'.", Arrays.equals(expected, actual));
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
		byte[] actual;
		byte[] expected;
		String password;
		String newInsertPassword;
		HashAlgorithm hashAlgorithm;

		password = "abcdefghijklmnopqrst";
		newInsertPassword = "abcdefghijklmnopqrst";
		hashAlgorithm = HashAlgorithm.SHA_512;
		expected = HashExtensions.hash(password.getBytes(), hashAlgorithm);
		actual = HashExtensions.hash(newInsertPassword.getBytes(), hashAlgorithm);

		assertTrue(expected.length == actual.length);
		assertTrue("'expected' should be equal with 'actual'.", Arrays.equals(expected, actual));
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
