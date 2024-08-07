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
package io.github.astrapi69.mystic.crypt.sha;

import static org.junit.jupiter.api.Assertions.assertEquals;

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

import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.crypt.api.algorithm.HashAlgorithm;
import io.github.astrapi69.random.object.RandomObjectFactory;

/**
 * The unit test class for the class {@link Hasher}
 */
public class HasherTest
{

	/**
	 * Test method for {@link Hasher#hashAndHex(String, String, HashAlgorithm, Charset)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown by get the byte array of the private key String object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws InvalidKeyException
	 *             the invalid key exception is thrown if initialization of the cipher object fails.
	 * @throws BadPaddingException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws IllegalBlockSizeException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 */
	@Test
	public void testHashAndHex() throws NoSuchAlgorithmException, InvalidKeyException,
		UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException,
		BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException
	{
		String actual;
		String expected;
		Charset charset;
		String password;
		String newInsertPassword;
		String salt;
		HashAlgorithm hashAlgorithm;

		charset = Charset.forName("UTF-8");
		password = "xxx";
		newInsertPassword = "xxx";
		salt = new String(RandomObjectFactory.randomSalt(8, charset), charset);
		hashAlgorithm = HashAlgorithm.SHA_512;
		expected = Hasher.hashAndHex(password, salt, hashAlgorithm, charset);
		actual = Hasher.hashAndHex(newInsertPassword, salt, hashAlgorithm, charset);
		assertEquals(actual, expected);
	}

	/**
	 * Test method for {@link Hasher#hashAndHex(String, String, String, HashAlgorithm, Charset)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown by get the byte array of the private key String object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws InvalidKeyException
	 *             the invalid key exception is thrown if initialization of the cipher object fails.
	 * @throws BadPaddingException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws IllegalBlockSizeException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 */
	@Test
	public void testHashAndHexWithPrivateKey() throws NoSuchAlgorithmException, InvalidKeyException,
		UnsupportedEncodingException, NoSuchPaddingException, IllegalBlockSizeException,
		BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException
	{
		String actual;
		String expected;
		Charset charset;
		String password;
		String newInsertPassword;
		String privateKey;
		String salt;
		HashAlgorithm hashAlgorithm;

		charset = Charset.forName("UTF-8");
		password = "xxx";
		newInsertPassword = "xxx";
		privateKey = new String(RandomObjectFactory.randomSalt(16, charset), charset);
		salt = new String(RandomObjectFactory.randomSalt(8, charset), charset);
		hashAlgorithm = HashAlgorithm.SHA_512;
		expected = Hasher.hashAndHex(password, privateKey, salt, hashAlgorithm, charset);
		actual = Hasher.hashAndHex(newInsertPassword, privateKey, salt, hashAlgorithm, charset);
		assertEquals(actual, expected);
	}

	/**
	 * Test method for {@link Hasher} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		BeanTester beanTester = new BeanTester();
		beanTester.testBean(Hasher.class);
	}

}
