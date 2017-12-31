package de.alpharogroup.auth;

import static org.testng.AssertJUnit.assertTrue;

import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import de.alpharogroup.collections.pairs.ValueBox;
import de.alpharogroup.test.objects.evaluations.EqualsEvaluator;
import de.alpharogroup.test.objects.evaluations.HashcodeEvaluator;
import de.alpharogroup.test.objects.evaluations.ToStringEvaluator;

public class CredentialsTest
{

	@Test
	public void testCredentials()
	{
		Credentials expected;
		Credentials actual;
		expected = Credentials.builder().build();
		actual = Credentials.builder().build();
		assertTrue(HashcodeEvaluator.evaluateEquality(expected, actual));
		assertTrue(ToStringEvaluator.evaluate(Credentials.class));
		assertTrue(ToStringEvaluator.evaluateConsistency(actual));

		actual = Credentials.builder().username("john").build();
		assertTrue(HashcodeEvaluator.evaluateUnequality(expected, actual));

		assertTrue(EqualsEvaluator.evaluateConsistency(expected, actual));
	}
	/**
	 * Test method for {@link ValueBox}
	 */
	@Test
	public void testWithBeanTester()
	{
		BeanTester beanTester = new BeanTester();
		beanTester.testBean(Credentials.class);
	}

}
