package de.alpharogroup.auth.beans;

import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

/**
 * The class {@link AuthenticationResult}.
 */
public class AuthenticationResultTest
{

	/**
	 * Test method for {@link AuthenticationResult}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(AuthenticationResult.class);
	}

}
