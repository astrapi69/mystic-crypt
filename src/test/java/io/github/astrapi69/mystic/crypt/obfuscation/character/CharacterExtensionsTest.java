/*
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
package io.github.astrapi69.mystic.crypt.obfuscation.character;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.test.base.AbstractTestCase;

/**
 * The unit test class for the class {@link CharacterExtensions}
 */
public class CharacterExtensionsTest extends AbstractTestCase<Boolean, Boolean>
{

	/**
	 * One case of the {@link CharacterExtensions#equalsIgnoreCase(Character, Character)} truth
	 * table; a record instead of a CSV source because half the cases carry {@code null}.
	 */
	record EqualsIgnoreCaseCase(String description, Character left, Character right,
		boolean expected) {
	}

	static Stream<EqualsIgnoreCaseCase> equalsIgnoreCaseCases()
	{
		return Stream.of(
			new EqualsIgnoreCaseCase("different case of the same letter", 'C', 'c', true),
			new EqualsIgnoreCaseCase("null against a character", null, 'c', false),
			new EqualsIgnoreCaseCase("a character against null", 'c', null, false),
			new EqualsIgnoreCaseCase("two different letters", 'c', 'd', false),
			new EqualsIgnoreCaseCase("null against null", null, null, true));
	}

	/**
	 * Test method for {@link CharacterExtensions#equalsIgnoreCase(Character, Character)}
	 *
	 * @param testCase
	 *            the truth-table case
	 */
	@ParameterizedTest
	@MethodSource("equalsIgnoreCaseCases")
	public void testEqualsIgnoreCase(EqualsIgnoreCaseCase testCase)
	{
		assertEquals(testCase.expected(),
			CharacterExtensions.equalsIgnoreCase(testCase.left(), testCase.right()),
			testCase.description());
	}

	/**
	 * Test method for {@link CharacterExtensions} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(CharacterExtensions.class);
	}

}
