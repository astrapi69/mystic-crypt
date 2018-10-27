package de.alpharogroup.crypto.obfuscation.experimental;

import static org.testng.AssertJUnit.assertEquals;

import java.lang.reflect.InvocationTargetException;

import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.collect.BiMap;

import de.alpharogroup.AbstractTestCase;
import de.alpharogroup.crypto.obfuscation.ObfuscationTestData;
import de.alpharogroup.crypto.obfuscation.rule.ObfuscationRule;

/**
 * The unit test class for the class {@link SimpleObfuscatorExtensions}
 */
public class SimpleObfuscatorExtensionsTest extends AbstractTestCase<String, String>
{

	Character character;
	Character replaceWith;
	ObfuscationRule<Character, Character> rule;
	BiMap<Character, ObfuscationRule<Character, Character>> rules;
	String stringToDisentangle;
	String stringToObfuscate;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 *
	 * @throws Exception
	 *             is thrown if an exception occurs
	 */
	@BeforeMethod
	protected void setUp() throws Exception
	{
		super.setUp();
		// create a rule for obfuscate the key
		rules = ObfuscationTestData.getFirstBiMapObfuscationRules();
	}	

	/**
	 * Test method for {@link SimpleObfuscatorExtensions#disentangle(BiMap, String)}
	 */
	@Test
	public void testDisentangle()
	{
		// new scenario...
		stringToDisentangle = "d";

//		actual = SimpleObfuscatorExtensions.disentangle(rules, stringToDisentangle);
//		expected = "d";
//		assertEquals(expected, actual);

		// new scenario...
		stringToDisentangle = "bcbd";

		actual = SimpleObfuscatorExtensions.disentangle(rules, stringToDisentangle);
		expected = "abac";
		assertEquals(expected, actual);
		// new scenario...
		stringToDisentangle = "Lfpobsep";

		actual = SimpleObfuscatorExtensions.disentangle(
			ObfuscationTestData.getFirstBiMapObfuscationRules(), stringToDisentangle);
		expected = "Lfpoasep";
		assertEquals(expected, actual);
		// new scenario...
		stringToDisentangle = "Lfpobsep Lpsfn jqtvn epmps tju bnfu, tfb dpotvm wfsufsfn qfsgfdup je. Amjj qspnqub fmfdusbn uf ofd, bu njojnvn dpqjptbf rvp. Ept jvejdp opnjobuj pqpsufsf fj, vtv bu ejdub mfhfoept. Io optusvn jotpmfot ejtqvuboep qsp, jvtup frvjefn jvt je.";

		actual = SimpleObfuscatorExtensions.disentangle(
			ObfuscationTestData.getFirstBiMapObfuscationRules(), stringToDisentangle);
		expected = "leonardo Lorem ipsum dolor sit amet, sea consul verterem perfecto id. Alii prompta electram te nec, at minimum copiosae quo. Eos iudico nominati oportere ei, usu at dicta legendos. In nostrum insolens disputando pro, iusto equidem ius id.";
		assertEquals(expected, actual);

		// new scenario...
		stringToDisentangle = "AcACd";

		actual = SimpleObfuscatorExtensions.disentangle(rules, stringToDisentangle);
		expected = "abacd";
		assertEquals(expected, actual);
		// new scenario...
		stringToDisentangle = "Lfpobsep";
	}

	/**
	 * Test method for {@link SimpleObfuscatorExtensions#obfuscateWith(BiMap, String)}
	 */
	@Test
	public void testObfuscateWith()
	{
		// new scenario...
		stringToObfuscate = "abac";

		actual = SimpleObfuscatorExtensions.obfuscateWith(rules, stringToObfuscate);
		expected = "bcbd";
		assertEquals(expected, actual);
		// new scenario...
		stringToObfuscate = "abacd";

		actual = SimpleObfuscatorExtensions.obfuscateWith(rules, stringToObfuscate);
		expected = "bcbde";
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link SimpleObfuscatorExtensions#validate(BiMap)}
	 */
	@Test
	public void testValidate()
	{
		boolean actual;
		boolean expected;
		BiMap<Character,ObfuscationRule<Character,Character>> biMap;
		
		biMap = ObfuscationTestData.getFirstBiMapObfuscationRules();
		actual = SimpleObfuscatorExtensions.validate(biMap);
		expected = true;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link SimpleObfuscatorExtensions} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(SimpleObfuscatorExtensions.class);
	}

}
