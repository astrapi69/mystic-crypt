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
package de.alpharogroup.crypto.pw;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import io.github.astrapi69.crypto.algorithm.HashAlgorithm;

/**
 * The unit test class for the class {@link PasswordEncryptor}
 */
public class PasswordEncryptorTest
{

	PasswordEncryptor instance;

	@BeforeMethod
	protected void setUp()
	{
		instance = PasswordEncryptor.getInstance();
	}

	/**
	 * Test method for {@link PasswordEncryptor#getInstance()}
	 */
	@Test
	public void testGetInstance()
	{
		assertNotNull(instance);
	}

	/**
	 * Test method for {@link PasswordEncryptor#getRandomPassword(int)}
	 */
	@Test
	public void testGetRandomPasswordInt()
	{
		String randomPassword = instance.getRandomPassword(8);
		assertNotNull(randomPassword);
		assertEquals(8, randomPassword.length());
	}

	/**
	 * Test method for {@link PasswordEncryptor#getRandomPassword(Optional)}
	 */
	@Test
	public void testGetRandomPasswordOptionalOfInteger()
	{
		String randomPassword = instance.getRandomPassword(Optional.of(8));
		assertNotNull(randomPassword);
		assertEquals(8, randomPassword.length());
	}

	/**
	 * Test method for {@link PasswordEncryptor#getRandomSalt()}
	 */
	@Test
	public void testGetRandomSalt()
	{
		String randomSalt = instance.getRandomSalt();
		assertNotNull(randomSalt);
		assertEquals(8, randomSalt.length());
	}

	/**
	 * Test method for {@link PasswordEncryptor#getRandomSalt(int)}
	 */
	@Test
	public void testGetRandomSaltInt()
	{
		String randomSalt = instance.getRandomSalt(8);
		assertNotNull(randomSalt);
		assertEquals(8, randomSalt.length());
	}

	/**
	 * Test method for {@link PasswordEncryptor#hashAndHexPassword(String, String)}
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
	public void testHashAndHexPasswordStringString()
		throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException,
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
		InvalidKeySpecException, InvalidAlgorithmParameterException
	{
		String actual;
		String expected;
		String salt;
		String password;
		salt = "uLc34JGr";
		password = "foo";
		actual = instance.hashAndHexPassword(password, salt);
		expected = "654FFC22A68F74C4E3DF480AE1FE8828EC5A3890ABCA6AFFBFCE772DB1E0E0900D96A3E63C2F2E8361960C9E4E30267B71D569A68C8DD3635531B89B9AAF6D9BEBC38BCA5F0543C8CD157D8F04133227CBDA8D4A8D243BC011EAF86E51EB4D3E4CF53B24BBEEC74904CD8D2811281338B6EF21FFADB4A5E83A04FF82FFDE96C0";
		assertEquals(expected, actual);
	}

	/**
	 * Test method for
	 * {@link PasswordEncryptor#hashAndHexPassword(String, String, HashAlgorithm, Charset)}
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
	public void testHashAndHexPasswordStringStringHashAlgorithmCharset()
		throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException,
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
		InvalidKeySpecException, InvalidAlgorithmParameterException
	{
		String actual;
		String expected;
		String salt;
		String password;
		HashAlgorithm hashAlgorithm;
		Charset charset;
		salt = "uLc34JGr";
		password = "foo";
		hashAlgorithm = HashAlgorithm.SHA_1;
		charset = StandardCharsets.UTF_8;

		actual = instance.hashAndHexPassword(password, salt, hashAlgorithm, charset);
		expected = "D3AF4F7472B54F73F6D4F1E80D9EFF45EE4303DBE481ACF4D25DFC581CAC739E9D2D51E6B01C536D34A444D224A82CE0";
		assertEquals(expected, actual);
	}

	/**
	 * Test method for
	 * {@link PasswordEncryptor#hashPassword(String, String, HashAlgorithm, Charset)}
	 * 
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails.
	 */
	@Test
	public void testHashPassword() throws NoSuchAlgorithmException
	{
		String actual;
		String salt;
		String password;
		HashAlgorithm hashAlgorithm;
		Charset charset;
		salt = "uLc34JGr";
		password = "foo";
		hashAlgorithm = HashAlgorithm.SHA_1;
		charset = StandardCharsets.UTF_8;
		actual = instance.hashPassword(password, salt, hashAlgorithm, charset);
		assertNotNull(actual);
	}

}
