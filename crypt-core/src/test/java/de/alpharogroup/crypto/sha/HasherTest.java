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
package de.alpharogroup.crypto.sha;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.log4j.Logger;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.HashAlgorithm;

/**
 * Test class for {@link Hasher}.
 */
public class HasherTest
{

	/** The Constant logger. */
	private static final Logger logger = Logger.getLogger(HasherTest.class.getName());

	/**
	 * Test method for {@link Hasher#hash(byte[], String, HashAlgorithm, Charset)}
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
		final String salt = new String(Hasher.getRandomSalt(8, charset), charset);
		final HashAlgorithm hashAlgorithm = HashAlgorithm.SHA_512;
		final  byte[] expected = Hasher.hash(password.getBytes(), salt, hashAlgorithm, charset);
		final  byte[] actual = Hasher.hash(newInsertPassword.getBytes(), salt, hashAlgorithm, charset);

		AssertJUnit.assertTrue(expected.length == actual.length);
		AssertJUnit.assertTrue("'expected' should be equal with 'actual'.", Arrays.equals(expected, actual));
	}

	/**
	 * Test method for {@link Hasher#hash(String, String, HashAlgorithm, Charset)}
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
		final String salt = new String(Hasher.getRandomSalt(8, charset), charset);
		final HashAlgorithm hashAlgorithm = HashAlgorithm.SHA_512;
		final String expected = Hasher.hash(password, salt, hashAlgorithm, charset);
		final String actual = Hasher.hash(newInsertPassword, salt, hashAlgorithm, charset);

		AssertJUnit.assertTrue("'expected' should be equal with 'actual'.",
			expected.equals(actual));
	}

	/**
	 * Test method for {@link Hasher#hashAndBase64(String, String, HashAlgorithm, Charset)}
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
		final String salt = new String(Hasher.getRandomSalt(8, charset), charset);
		final HashAlgorithm hashAlgorithm = HashAlgorithm.SHA_512;
		final String expected = Hasher.hashAndBase64(password, salt, hashAlgorithm, charset);
		final String actual = Hasher.hashAndBase64(newInsertPassword, salt, hashAlgorithm, charset);
		AssertJUnit.assertTrue("'expected' should be equal with 'actual'.",
			expected.equals(actual));
	}

	/**
	 * Test method for {@link Hasher#hashAndHex(String, String, HashAlgorithm, Charset)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown by get the byte array of the private key String object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeyException
	 *             the invalid key exception is thrown if initialization of the cypher object fails.
	 * @throws BadPaddingException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws IllegalBlockSizeException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 */
	@Test
	public void testHashAndHex() throws NoSuchAlgorithmException, InvalidKeyException,
		UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException,
		BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException
	{
		final Charset charset = Charset.forName("UTF-8");
		final String password = "xxx";
		final String newInsertPassword = "xxx";
		final String salt = new String(Hasher.getRandomSalt(8, charset), charset);
		final HashAlgorithm hashAlgorithm = HashAlgorithm.SHA_512;
		final String expected = Hasher.hashAndHex(password, salt, hashAlgorithm, charset);
		final String actual = Hasher.hashAndHex(newInsertPassword, salt, hashAlgorithm, charset);
		logger.debug("salt:" + salt);
		logger.debug("expected:" + expected);
		logger.debug("actual:" + actual);
		AssertJUnit.assertTrue("'expected' should be equal with 'actual'.",
			expected.equals(actual));
	}

}
