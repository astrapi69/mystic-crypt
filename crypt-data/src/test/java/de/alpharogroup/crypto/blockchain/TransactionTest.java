package de.alpharogroup.crypto.blockchain;

import static org.testng.AssertJUnit.assertNotNull;
import static org.testng.AssertJUnit.assertEquals;

import java.lang.reflect.InvocationTargetException;

import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import de.alpharogroup.evaluate.object.evaluators.SilentEqualsHashCodeAndToStringEvaluator;

/**
 * The unit test class for the class {@link Transaction}
 */
public class TransactionTest
{

	/**
	 * Test method for {@link Transaction} constructors
	 */
	@Test
	public final void testConstructors()
	{
		Transaction object;
		
		object = new Transaction();
		assertNotNull(object);	
	}	

	/**
	 * Test method for {@link Transaction#equals(Object)} , {@link Transaction#hashCode()} and
	 * {@link Transaction#toString()}
	 */
	@Test(enabled = false)
	public void testEqualsHashcodeAndToStringWithClass()
	{
		boolean expected;
		boolean actual;

		actual = SilentEqualsHashCodeAndToStringEvaluator
			.evaluateEqualsHashcodeAndToStringQuietly(Transaction.class);
		expected = true;
		assertEquals(expected, actual);
	}
	

	/**
	 * Test method for {@link Transaction} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(Transaction.class);
	}

}
