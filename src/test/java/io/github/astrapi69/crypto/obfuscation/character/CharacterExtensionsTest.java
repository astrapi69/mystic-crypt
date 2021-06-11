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
package io.github.astrapi69.crypto.obfuscation.character;

import static org.testng.AssertJUnit.assertEquals;

import io.github.astrapi69.crypto.obfuscation.character.CharacterExtensions;
import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import io.github.astrapi69.AbstractTestCase;

/**
 * The unit test class for the class {@link CharacterExtensions}
 */
public class CharacterExtensionsTest extends AbstractTestCase<Boolean, Boolean>
{

	/**
	 * Test method for {@link CharacterExtensions#equalsIgnoreCase(Character, Character)}
	 */
	@Test(enabled = true)
	public void testEqualsIgnoreCase()
	{

		expected = true;
		actual = CharacterExtensions.equalsIgnoreCase(Character.valueOf('C'),
			Character.valueOf('c'));
		assertEquals(expected, actual);

		expected = false;
		actual = CharacterExtensions.equalsIgnoreCase(null, Character.valueOf('c'));
		assertEquals(expected, actual);

		expected = true;
		actual = CharacterExtensions.equalsIgnoreCase(null, null);

		assertEquals(expected, actual);
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