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
 * The unit test class for the class {@link CharacterObfuscator}.
 */
@FieldDefaults(level = AccessLevel.PRIVATE)
public class CharacterObfuscatorTest
{

	String actual;
	String expected;
	String stringToObfuscate;
	BiMap<Character, ObfuscationOperationRule<Character, Character>> rules;
	Character character;
	Character replaceWith;
	Operation operation;
	Set<Integer> indexes;
	ObfuscationOperationRule<Character, Character> rule;
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
		replaceWith = 'b';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0, 2);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('b');
		replaceWith = 'c';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(2);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('c');
		replaceWith = 'd';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(3);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('d');
		replaceWith = 'e';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('e');
		replaceWith = 'f';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('f');
		replaceWith = 'g';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('g');
		replaceWith = 'h';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('h');
		replaceWith = 'i';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('i');
		replaceWith = 'j';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('j');
		replaceWith = 'k';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('k');
		replaceWith = 'l';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('l');
		replaceWith = 'm';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('m');
		replaceWith = 'n';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('n');
		replaceWith = 'o';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('o');
		replaceWith = 'p';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('p');
		replaceWith = 'q';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('q');
		replaceWith = 'r';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('r');
		replaceWith = 's';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('s');
		replaceWith = 't';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('t');
		replaceWith = 'u';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('u');
		replaceWith = 'v';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('v');
		replaceWith = 'w';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('w');
		replaceWith = 'x';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('x');
		replaceWith = 'y';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('y');
		replaceWith = 'z';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
			.replaceWith(replaceWith).operation(operation).indexes(indexes).build();
		rules.put(character, rule);

		character = Character.valueOf('z');
		replaceWith = '0';
		operation = Operation.UPPERCASE;
		indexes = SetExtensions.newHashSet(0);
		rule = ObfuscationOperationRule.<Character, Character> newRule().character(character)
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
	 * Test method for {@link CharacterObfuscator#disentangle()}.
	 */
	@Test
	public void testDisentangle()
	{
		stringToObfuscate = "abac";
		// obfuscate the key
		obfuscator = new CharacterObfuscator(rules, stringToObfuscate);
		actual = obfuscator.obfuscate();
		expected = "AcAC";
		assertEquals(expected, actual);

		actual = obfuscator.disentangle();
		expected = stringToObfuscate;
		assertEquals(expected, actual);
	}

	@Test
	public void testObfuscate()
	{
		// a key for obfuscation
		stringToObfuscate = "abac";

		// obfuscate the key
		obfuscator = new CharacterObfuscator(rules, stringToObfuscate);
		actual = obfuscator.obfuscate();
		expected = "AcAC";
		assertEquals(expected, actual);

		actual = obfuscator.disentangle();
		expected = stringToObfuscate;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CharacterObfuscator#obfuscate()}.
	 */
	@Test
	public void testObfuscateEightChars()
	{
		// a key for obfuscation
		stringToObfuscate = "leonardo";

		// obfuscate the key
		obfuscator = new CharacterObfuscator(rules, stringToObfuscate);
		actual = obfuscator.obfuscate();
		expected = "Lfpobsep";
		assertEquals(expected, actual);

		actual = obfuscator.disentangle();
		expected = stringToObfuscate;
		assertEquals(expected, actual);
	}

}
