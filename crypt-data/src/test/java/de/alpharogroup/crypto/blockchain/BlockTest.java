package de.alpharogroup.crypto.blockchain;

import static org.testng.AssertJUnit.assertNotNull;
import static org.testng.AssertJUnit.assertEquals;

import java.lang.reflect.InvocationTargetException;

import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import de.alpharogroup.evaluate.object.evaluators.SilentEqualsHashCodeAndToStringEvaluator;

/**
 * The unit test class for the class {@link Block}
 */
public class BlockTest
{

	/**
	 * Test method for {@link Block} constructors
	 */
	@Test
	public final void testConstructors()
	{
		Block block;
		
		block = new Block();
		assertNotNull(block);	
	}	

	/**
	 * Test method for {@link Block#equals(Object)} , {@link Block#hashCode()} and
	 * {@link Block#toString()}
	 */
	@Test(enabled = false)
	public void testEqualsHashcodeAndToStringWithClass()
	{
		boolean expected;
		boolean actual;

		actual = SilentEqualsHashCodeAndToStringEvaluator
			.evaluateEqualsHashcodeAndToStringQuietly(Block.class);
		expected = true;
		assertEquals(expected, actual);
	}
	

	/**
	 * Test method for {@link Block} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(Block.class);
	}
}
