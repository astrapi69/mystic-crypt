package de.alpharogroup.crypto.obfuscation.rules;

import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

public class SimpleObfuscationRulesTest
{

	@Test
	public void testWithBeanTester()
	{
		BeanTester beanTester = new BeanTester();
		beanTester.testBean(SimpleObfuscationRules.class);
	}

}
