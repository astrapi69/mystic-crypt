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
package io.github.astrapi69.crypto.simple;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.util.Comparator;
import java.util.List;

import org.testng.annotations.Test;

import io.github.astrapi69.collection.CollectionExtensions;
import io.github.astrapi69.collection.array.ArrayFactory;
import io.github.astrapi69.collection.list.ListFactory;
import io.github.astrapi69.string.StringExtensions;

/**
 * The unit test class for the class {@link CharacterSetEncryptor}
 */
public class CharacterSetEncryptorTest
{

	/**
	 * Test method for the {@link CharacterSetEncryptor#encrypt(String)} method
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public void testEncrypt() throws Exception
	{
		List<Integer> actual;
		List<Integer> expected;
		List<Character> randomDefinedOrderCharacters;
		List<Character> expectedUniqueCharacters;
		String text;
		List<Character> uniqueCharacters;
		CharacterSetEncryptor encryptor;
		// new scenario with ordered character set...
		char[] expectedChars = ArrayFactory.newCharArray(' ', ',', '.', 'A', 'E', 'I', 'L', 'a',
			'c', 'd', 'e', 'f', 'g', 'i', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v');
		expectedUniqueCharacters = ListFactory.newCharacterArrayList(null, expectedChars);

		text = "Lorem ipsum dolor sit amet, sea consul verterem perfecto id. Alii prompta electram te nec, at minimum copiosae quo. Eos iudico nominati oportere ei, usu at dicta legendos. In nostrum insolens disputando pro, iusto equidem ius id.";
		uniqueCharacters = StringExtensions.newCharacterList(text, Comparator.naturalOrder());
		assertTrue(
			CollectionExtensions.isEqualCollection(uniqueCharacters, expectedUniqueCharacters));
		encryptor = new CharacterSetEncryptor(uniqueCharacters);
		actual = encryptor.encrypt(text);
		expected = ListFactory.newArrayList(6, 17, 20, 10, 15, 0, 13, 18, 21, 23, 15, 0, 9, 17, 14,
			17, 20, 0, 21, 13, 22, 0, 7, 15, 10, 22, 1, 0, 21, 10, 7, 0, 8, 17, 16, 21, 23, 14, 0,
			24, 10, 20, 22, 10, 20, 10, 15, 0, 18, 10, 20, 11, 10, 8, 22, 17, 0, 13, 9, 2, 0, 3, 14,
			13, 13, 0, 18, 20, 17, 15, 18, 22, 7, 0, 10, 14, 10, 8, 22, 20, 7, 15, 0, 22, 10, 0, 16,
			10, 8, 1, 0, 7, 22, 0, 15, 13, 16, 13, 15, 23, 15, 0, 8, 17, 18, 13, 17, 21, 7, 10, 0,
			19, 23, 17, 2, 0, 4, 17, 21, 0, 13, 23, 9, 13, 8, 17, 0, 16, 17, 15, 13, 16, 7, 22, 13,
			0, 17, 18, 17, 20, 22, 10, 20, 10, 0, 10, 13, 1, 0, 23, 21, 23, 0, 7, 22, 0, 9, 13, 8,
			22, 7, 0, 14, 10, 12, 10, 16, 9, 17, 21, 2, 0, 5, 16, 0, 16, 17, 21, 22, 20, 23, 15, 0,
			13, 16, 21, 17, 14, 10, 16, 21, 0, 9, 13, 21, 18, 23, 22, 7, 16, 9, 17, 0, 18, 20, 17,
			1, 0, 13, 23, 21, 22, 17, 0, 10, 19, 23, 13, 9, 10, 15, 0, 13, 23, 21, 0, 13, 9, 2);
		assertEquals(actual, expected);
		// new scenario with random ordered character set...
		char[] randomDefinedOrderChars = ArrayFactory.newCharArray('f', ' ', 'p', 'E', '.', 's',
			'e', 't', 'A', 'v', 'd', 'c', 'a', 'o', 'q', 'r', 'L', 'g', 'u', 'm', 'l', 'I', 'i',
			',', 'n');
		randomDefinedOrderCharacters = ListFactory.newCharacterArrayList(null,
			randomDefinedOrderChars);
		encryptor = new CharacterSetEncryptor(randomDefinedOrderCharacters);
		actual = encryptor.encrypt(text);
		expected = ListFactory.newArrayList(16, 13, 15, 6, 19, 1, 22, 2, 5, 18, 19, 1, 10, 13, 20,
			13, 15, 1, 5, 22, 7, 1, 12, 19, 6, 7, 23, 1, 5, 6, 12, 1, 11, 13, 24, 5, 18, 20, 1, 9,
			6, 15, 7, 6, 15, 6, 19, 1, 2, 6, 15, 0, 6, 11, 7, 13, 1, 22, 10, 4, 1, 8, 20, 22, 22, 1,
			2, 15, 13, 19, 2, 7, 12, 1, 6, 20, 6, 11, 7, 15, 12, 19, 1, 7, 6, 1, 24, 6, 11, 23, 1,
			12, 7, 1, 19, 22, 24, 22, 19, 18, 19, 1, 11, 13, 2, 22, 13, 5, 12, 6, 1, 14, 18, 13, 4,
			1, 3, 13, 5, 1, 22, 18, 10, 22, 11, 13, 1, 24, 13, 19, 22, 24, 12, 7, 22, 1, 13, 2, 13,
			15, 7, 6, 15, 6, 1, 6, 22, 23, 1, 18, 5, 18, 1, 12, 7, 1, 10, 22, 11, 7, 12, 1, 20, 6,
			17, 6, 24, 10, 13, 5, 4, 1, 21, 24, 1, 24, 13, 5, 7, 15, 18, 19, 1, 22, 24, 5, 13, 20,
			6, 24, 5, 1, 10, 22, 5, 2, 18, 7, 12, 24, 10, 13, 1, 2, 15, 13, 23, 1, 22, 18, 5, 7, 13,
			1, 6, 14, 18, 22, 10, 6, 19, 1, 22, 18, 5, 1, 22, 10, 4);
		assertEquals(actual, expected);
	}

}
