package de.alpharogroup.crypto.obfuscation;

import static org.testng.AssertJUnit.assertEquals;

import org.testng.annotations.Test;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import de.alpharogroup.collections.set.SetExtensions;
import de.alpharogroup.crypto.obfuscation.api.Obfuscatable;
import de.alpharogroup.crypto.obfuscation.rule.ObfuscationOperationRule;
import de.alpharogroup.crypto.obfuscation.rule.Operation;

/**
 * The unit test class for the class {@link ComplexObfuscator}.
 */
public class ComplexObfuscatorTest
{

	/**
	 * Test method for {@link ComplexObfuscator#disentangle()}.
	 */
	@Test
	public void testDisentangle()
	{

		String actual;
		String expected;
		ObfuscationOperationRule<Character, String> rule;
		// a key for obfuscation
		String toObfuscatedString = "abac";
		// create a rule for obfuscate the key

		BiMap<Character, ObfuscationOperationRule<Character, String>> rules = HashBiMap.create();
		rule = ObfuscationOperationRule.<Character, String>newRule()
			.character(Character.valueOf('a'))
			.replaceWith("bc")
			.operation(Operation.UPPERCASE)
			.indexes(SetExtensions.newHashSet(0,2))
			.build();
		rules.put(Character.valueOf('a'), rule);

		rule = ObfuscationOperationRule.<Character, String>newRule()
			.character(Character.valueOf('b'))
			.replaceWith("cd")
			.operation(Operation.UPPERCASE)
			.indexes(SetExtensions.newHashSet(2))
			.build();
		rules.put(Character.valueOf('b'), rule);

		rule = ObfuscationOperationRule.<Character, String>newRule()
			.character(Character.valueOf('c'))
			.replaceWith("de")
			.operation(Operation.UPPERCASE)
			.indexes(SetExtensions.newHashSet(3))
			.build();
		rules.put(Character.valueOf('c'), rule);

		// obfuscate the key
		Obfuscatable obfuscator = new ComplexObfuscator(rules, toObfuscatedString);
		actual = obfuscator.obfuscate();
		expected = "AcdAC";
		assertEquals(expected, actual);


		actual = obfuscator.disentangle();
		expected = toObfuscatedString;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link ComplexObfuscator#obfuscate()}.
	 */
	@Test
	public void testObfuscate()
	{
		String actual;
		String expected;
		ObfuscationOperationRule<Character, String> rule;
		// a key for obfuscation
		String toObfuscatedString = "abac";
		// create a rule for obfuscate the key

		BiMap<Character, ObfuscationOperationRule<Character, String>> rules = HashBiMap.create();
		rule = ObfuscationOperationRule.<Character, String>newRule()
			.character(Character.valueOf('a'))
			.replaceWith("bc")
			.operation(Operation.UPPERCASE)
			.indexes(SetExtensions.newHashSet(0,2))
			.build();
		rules.put(Character.valueOf('a'), rule);

		rule = ObfuscationOperationRule.<Character, String>newRule()
			.character(Character.valueOf('b'))
			.replaceWith("cd")
			.operation(Operation.UPPERCASE)
			.indexes(SetExtensions.newHashSet(2))
			.build();
		rules.put(Character.valueOf('b'), rule);

		rule = ObfuscationOperationRule.<Character, String>newRule()
			.character(Character.valueOf('c'))
			.replaceWith("de")
			.operation(Operation.UPPERCASE)
			.indexes(SetExtensions.newHashSet(3))
			.build();
		rules.put(Character.valueOf('c'), rule);

		// obfuscate the key
		Obfuscatable obfuscator = new ComplexObfuscator(rules, toObfuscatedString);
		actual = obfuscator.obfuscate();
		expected = "AcdAC";
		assertEquals(expected, actual);
	}

}
