package de.alpharogroup.crypto.obfuscation;

import static org.testng.AssertJUnit.assertEquals;

import java.util.Set;

import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import de.alpharogroup.collections.set.SetExtensions;
import de.alpharogroup.crypto.obfuscation.api.Obfuscatable;
import de.alpharogroup.crypto.obfuscation.rule.ObfuscationOperationRule;
import de.alpharogroup.crypto.obfuscation.rule.Operation;
import lombok.AccessLevel;
import lombok.experimental.FieldDefaults;

/**
 * The unit test class for the class {@link ComplexObfuscator}.
 */
@FieldDefaults(level = AccessLevel.PRIVATE)
public class ComplexObfuscatorTest
{

	String actual;
	String expected;
	String stringToObfuscate;
	BiMap<Character, ObfuscationOperationRule<Character, String>> rules;
	Character character;
	String replaceWith;
	Operation operation;
	Set<Integer> indexes;
	ObfuscationOperationRule<Character, String> rule;
	Obfuscatable obfuscator;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 *
	 * @throws Exception
	 *             is thrown if an exception occurs
	 */
	@BeforeMethod
	protected void setUp() throws Exception
	{
		// create a rule for obfuscate the key
		rules = HashBiMap.create();

		character = Character.valueOf('a');
		replaceWith = "bc";
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0, 2);
		rule = ObfuscationOperationRule.<Character, String> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('b');
		replaceWith = "cd";
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(2);
		rule = ObfuscationOperationRule.<Character, String> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('c');
		replaceWith = "de";
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(3);
		rule = ObfuscationOperationRule.<Character, String> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('d');
		replaceWith = "ef";
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(3);
		rule = ObfuscationOperationRule.<Character, String> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('e');
		replaceWith = "fg";
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(3);
		rule = ObfuscationOperationRule.<Character, String> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('f');
		replaceWith = "gh";
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(3);
		rule = ObfuscationOperationRule.<Character, String> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('g');
		replaceWith = "hi";
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(3);
		rule = ObfuscationOperationRule.<Character, String> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('h');
		replaceWith = "ijk";
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(3);
		rule = ObfuscationOperationRule.<Character, String> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);
	}

	/**
	 * Tear down method will be invoked after every unit test method in this class
	 *
	 * @throws Exception
	 *             is thrown if an exception occurs
	 */
	@AfterMethod
	protected void tearDown() throws Exception
	{
		actual = null;
		expected = null;
		stringToObfuscate = null;
		rules = null;
		character = null;
		replaceWith = null;
		operation = null;
		indexes = null;
		rule = null;
		obfuscator = null;
	}

	/**
	 * Test method for {@link ComplexObfuscator#disentangle()}.
	 */
	@Test
	public void testDisentangle()
	{
		stringToObfuscate = "abac";
		// obfuscate the key
		obfuscator = new ComplexObfuscator(rules, stringToObfuscate);
		actual = obfuscator.obfuscate();
		expected = "AcdAC";
		assertEquals(expected, actual);

		actual = obfuscator.disentangle();
		expected = stringToObfuscate;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link ComplexObfuscator#obfuscate()}.
	 */
	@Test
	public void testObfuscate()
	{
		// a key for obfuscation
		stringToObfuscate = "abac";

		// obfuscate the key
		obfuscator = new ComplexObfuscator(rules, stringToObfuscate);
		actual = obfuscator.obfuscate();
		expected = "AcdAC";
		assertEquals(expected, actual);
	}

}
