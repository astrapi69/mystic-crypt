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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.Map;
import java.util.Optional;

import org.testng.annotations.Test;

import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;

import de.alpharogroup.collections.map.MapFactory;
import de.alpharogroup.evaluate.object.api.ContractViolation;
import de.alpharogroup.evaluate.object.checkers.EqualsHashCodeAndToStringCheck;

/**
 * The class {@link CharacterObfuscationRules}
 */
public class CharacterObfuscationRulesTest
{

	/**
	 * Test method for {@link CharacterObfuscationRules} constructors and builders
	 */
	@Test
	public final void testConstructors()
	{
		final Map<Character, Character> charmap = MapFactory.newHashMap();

		charmap.put(Character.valueOf('1'), Character.valueOf('I'));
		charmap.put(Character.valueOf('2'), Character.valueOf('S'));
		charmap.put(Character.valueOf('3'), Character.valueOf('E'));
		BiMap<Character, Character> obfuscationRules = HashBiMap.create(charmap);
		CharacterObfuscationRules model = new CharacterObfuscationRules(obfuscationRules);
		assertNotNull(model);
		model = CharacterObfuscationRules.rulesBuilder().obfuscationRules(obfuscationRules).build();
		assertNotNull(model);
	}

	/**
	 * Test method for {@link CharacterObfuscationRules#equals(Object)} ,
	 * {@link CharacterObfuscationRules#hashCode()} and {@link CharacterObfuscationRules#toString()}
	 *
	 * @throws IllegalAccessException
	 *             if the caller does not have access to the property accessor method
	 * @throws InstantiationException
	 *             if a new instance of the bean's class cannot be instantiated
	 * @throws InvocationTargetException
	 *             if the property accessor method throws an exception
	 * @throws NoSuchMethodException
	 *             if an accessor method for this property cannot be found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred
	 */
	@Test
	public void testEqualsHashcodeAndToStringWithClass() throws NoSuchMethodException,
		IllegalAccessException, InvocationTargetException, InstantiationException, IOException
	{
		Optional<ContractViolation> expected;
		Optional<ContractViolation> actual;

		final Map<Character, Character> charmap = MapFactory.newHashMap();
		final Map<Character, Character> charmap2 = MapFactory.newHashMap();

		charmap.put(Character.valueOf('1'), Character.valueOf('I'));
		charmap.put(Character.valueOf('2'), Character.valueOf('F'));
		charmap.put(Character.valueOf('3'), Character.valueOf('E'));

		charmap2.put(Character.valueOf('4'), Character.valueOf('A'));
		charmap2.put(Character.valueOf('5'), Character.valueOf('S'));
		charmap2.put(Character.valueOf('6'), Character.valueOf('G'));

		BiMap<Character, Character> obfuscationRules = HashBiMap.create(charmap);


		final CharacterObfuscationRules first = new CharacterObfuscationRules(obfuscationRules);
		final CharacterObfuscationRules second = new CharacterObfuscationRules(
			HashBiMap.create(MapFactory.newHashMap(charmap2)));
		final CharacterObfuscationRules third = new CharacterObfuscationRules(obfuscationRules);
		final CharacterObfuscationRules fourth = new CharacterObfuscationRules(obfuscationRules);

		actual = EqualsHashCodeAndToStringCheck.equalsHashcodeAndToString(first, second, third,
			fourth);
		expected = Optional.empty();
		assertEquals(expected, actual);
	}

}
