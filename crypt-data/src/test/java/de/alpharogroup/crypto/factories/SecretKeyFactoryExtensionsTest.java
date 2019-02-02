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
/**
 *
 */
package de.alpharogroup.crypto.factories;

import static org.testng.Assert.assertNotNull;

import java.lang.reflect.InvocationTargetException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.algorithm.AesAlgorithm;
import de.alpharogroup.crypto.algorithm.SunJCEAlgorithm;

/**
 * The unit test class for the class {@link SecretKeyFactoryExtensions}
 */
public class SecretKeyFactoryExtensionsTest
{

	/**
	 * Test method for {@link SecretKeyFactoryExtensions#newSecretKey(char[], String)}
	 */
	@Test
	public void testNewSecretKey() throws Exception
	{
		String algorithm;
		SecretKey secretKey;

		algorithm = SunJCEAlgorithm.PBEWithMD5AndDES.getAlgorithm();
		secretKey = SecretKeyFactoryExtensions.newSecretKey("secret".toCharArray(), algorithm);
		assertNotNull(secretKey);
	}

	/**
	 * Test method for {@link SecretKeyFactoryExtensions#newSecretKeyFactory(String)}
	 */
	@Test
	public void testNewSecretKeyFactory() throws Exception
	{
		String algorithm;
		SecretKeyFactory secretKeyFactory;

		algorithm = CryptConst.PBE_WITH_MD5_AND_DES;
		secretKeyFactory = SecretKeyFactoryExtensions.newSecretKeyFactory(algorithm);
		assertNotNull(secretKeyFactory);
	}

	/**
	 * Test method for {@link SecretKeyFactoryExtensions#newSecretKeySpec(byte[], String)}
	 */
	@Test
	public void testNewSecretKeySpecByteArrayString() throws Exception
	{
		String algorithm;
		String key;
		SecretKeySpec secretKeySpec;

		algorithm = AesAlgorithm.AES.getAlgorithm();
		key = "1234567890123456";
		secretKeySpec = SecretKeyFactoryExtensions.newSecretKeySpec(key.getBytes(), algorithm);
		assertNotNull(secretKeySpec);
	}

	/**
	 * Test method for {@link SecretKeyFactoryExtensions#newSecretKeySpec(String, int)}
	 */
	@Test
	public void testNewSecretKeySpecStringInt() throws Exception
	{
		String algorithm;
		SecretKeySpec secretKeySpec;

		algorithm = AesAlgorithm.AES.getAlgorithm();
		secretKeySpec = SecretKeyFactoryExtensions.newSecretKeySpec(algorithm, 128);
		assertNotNull(secretKeySpec);
	}

	/**
	 * Test method for {@link SecretKeyFactoryExtensions} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(SecretKeyFactoryExtensions.class);
	}

}
