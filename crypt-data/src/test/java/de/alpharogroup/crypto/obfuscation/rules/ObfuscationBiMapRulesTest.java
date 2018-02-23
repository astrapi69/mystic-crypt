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
package de.alpharogroup.crypto.obfuscation.rules;

import static org.testng.AssertJUnit.assertEquals;

import java.lang.reflect.InvocationTargetException;
import java.util.Map;

import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import de.alpharogroup.collections.map.MapExtensions;
import de.alpharogroup.test.objects.evaluations.EqualsHashCodeAndToStringEvaluator;

/**
 * The unit test class for the class {@link SimpleObfuscationRules}.
 */
public class ObfuscationBiMapRulesTest
{

	/**
	 * Test method for {@link SimpleObfuscationRules#equals(Object)} ,
	 * {@link SimpleObfuscationRules#hashCode()} and {@link SimpleObfuscationRules#toString()}
	 */
	@Test
	public void testEqualsHashcodeAndToString()
	{

		boolean expected;
		boolean actual;

		final Map<String, String> charmap = MapExtensions.newHashMap();

		charmap.put("1", "O");
		charmap.put("2", "Tw");
		charmap.put("3", "Th");
		charmap.put("4", "Fo");
		charmap.put("5", "Fi");
		charmap.put("6", "Si");
		charmap.put("7", "Se");
		charmap.put("8", "E");
		charmap.put("9", "N");
		BiMap<String, String> obfuscationRules = HashBiMap.create(charmap);

		Map<String, String> map = MapExtensions.newHashMap();

		map.put("1", "O");

		final SimpleObfuscationRules first = SimpleObfuscationRules.buildRule()
			.obfuscationRules(obfuscationRules).build();
		final SimpleObfuscationRules second = new SimpleObfuscationRules(HashBiMap.create(map));
		final SimpleObfuscationRules third = new SimpleObfuscationRules(obfuscationRules);
		final SimpleObfuscationRules fourth = new SimpleObfuscationRules(obfuscationRules);

		actual = EqualsHashCodeAndToStringEvaluator.evaluateEqualsHashcodeAndToString(first, second,
			third, fourth);
		expected = true;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link SimpleObfuscationRules}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(SimpleObfuscationRules.class);
	}

}
