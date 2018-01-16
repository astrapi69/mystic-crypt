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
package de.alpharogroup.crypto.obfuscation.rule;

import static org.testng.AssertJUnit.assertEquals;

import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import de.alpharogroup.collections.set.SetExtensions;
import de.alpharogroup.test.objects.evaluations.EqualsHashCodeAndToStringEvaluator;

public class ObfuscationOperationRuleTest
{

	@Test
	public void testObfuscationOperationRule()
	{
		Object expected;
		Object actual;
		ObfuscationOperationRule<Character, String> rule = ObfuscationOperationRule
			.<Character, String> newRule().character(Character.valueOf('a')).replaceWith("bc")
			.operation(Operation.UPPERCASE).indexes(SetExtensions.newHashSet(0, 2)).build();

		expected = Character.valueOf('a');
		actual = rule.getCharacter();

		assertEquals(actual, expected);

		expected = "bc";
		actual = rule.getReplaceWith();

		assertEquals(actual, expected);

		expected = Operation.UPPERCASE;
		actual = rule.getOperation();

		assertEquals(actual, expected);

		expected = SetExtensions.newHashSet(0, 2);
		actual = rule.getIndexes();

		assertEquals(actual, expected);

		EqualsHashCodeAndToStringEvaluator.evaluateEqualsHashcodeAndToString(rule);
	}

	@Test
	public void testWithBeanTester()
	{
		BeanTester beanTester = new BeanTester();
		beanTester.testBean(ObfuscationOperationRule.class);
	}
}
