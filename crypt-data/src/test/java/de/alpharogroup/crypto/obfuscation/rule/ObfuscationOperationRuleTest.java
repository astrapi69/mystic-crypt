package de.alpharogroup.crypto.obfuscation.rule;

import static org.testng.AssertJUnit.assertEquals;

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
		ObfuscationOperationRule<Character, String> rule = ObfuscationOperationRule.<Character, String>newRule()
			.character(Character.valueOf('a'))
			.replaceWith("bc")
			.operation(Operation.UPPERCASE)
			.indexes(SetExtensions.newHashSet(0,2))
			.build();

		expected = Character.valueOf('a');
		actual = rule.getCharacter();

		assertEquals(actual, expected);

		expected = "bc";
		actual = rule.getReplaceWith();

		assertEquals(actual, expected);

		expected = Operation.UPPERCASE;
		actual = rule.getOperation();

		assertEquals(actual, expected);

		expected = SetExtensions.newHashSet(0,2);
		actual = rule.getIndexes();

		assertEquals(actual, expected);

		EqualsHashCodeAndToStringEvaluator.evaluateEqualsHashcodeAndToString(rule);
	}

}
