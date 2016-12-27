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

}
