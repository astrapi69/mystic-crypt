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
package de.alpharogroup.random;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import org.testng.AssertJUnit;
import org.testng.annotations.Test;

/**
 * The class {@link SecureRandomBeanTest}.
 */
public class SecureRandomBeanTest
{

	/**
	 * Test method for {@link SecureRandomBean#build()} .
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if a SecureRandomSpi implementation for the specified algorithm is not
	 *             available from the specified provider.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test
	public void testBuild() throws NoSuchAlgorithmException, NoSuchProviderException
	{
		SecureRandom sr = SecureRandomBean.builder().build();

		sr = SecureRandomBean.builder().algorithm(SecureRandomBean.DEFAULT_ALGORITHM).build();
		AssertJUnit.assertNotNull(sr);
		sr = SecureRandomBean.builder().algorithm(SecureRandomBean.DEFAULT_ALGORITHM)
			.provider("SUN").build();
		AssertJUnit.assertNotNull(sr);
	}

	/**
	 * Test method for {@link SecureRandomBean#build()} with null value for the algorithm.
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if a SecureRandomSpi implementation for the specified algorithm is not
	 *             available from the specified provider.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test(expectedExceptions = NullPointerException.class)
	public void testBuildWithNullAlgorithm()
		throws NoSuchAlgorithmException, NoSuchProviderException
	{
		SecureRandomBean.builder().algorithm(null).build();
	}

	/**
	 * Test method for {@link SecureRandomBean#build()} with null value for the algorithm.
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if a SecureRandomSpi implementation for the specified algorithm is not
	 *             available from the specified provider.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test(expectedExceptions = NullPointerException.class)
	public void testBuildWithNullProvider() throws NoSuchAlgorithmException, NoSuchProviderException
	{
		SecureRandomBean.builder().provider(null).build();
	}

}
