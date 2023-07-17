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
package io.github.astrapi69.mystic.crypt.simple;

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
 * The unit test class for the class {@link CharacterSetDecryptor}
 */
public class CharacterSetDecryptorTest
{

	/**
	 * Test method for the {@link CharacterSetDecryptor#decrypt(List)} method
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public void testDecrypt() throws Exception
	{
		String actual;
		String expected;
		List<Integer> encryptedIntegerList;
		List<Character> randomDefinedOrderCharacters;
		List<Character> expectedUniqueCharacters;
		String text;
		List<Character> uniqueCharacters;
		CharacterSetEncryptor encryptor;
		CharacterSetDecryptor decryptor;
		// new scenario with ordered character set...
		char[] expectedChars = ArrayFactory.newCharArray(' ', ',', '.', 'A', 'E', 'I', 'L', 'a',
			'c', 'd', 'e', 'f', 'g', 'i', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v');
		expectedUniqueCharacters = ListFactory.newCharacterArrayList(null, expectedChars);

		text = "Lorem ipsum dolor sit amet, sea consul verterem perfecto id. Alii prompta electram te nec, at minimum copiosae quo. Eos iudico nominati oportere ei, usu at dicta legendos. In nostrum insolens disputando pro, iusto equidem ius id.";
		uniqueCharacters = StringExtensions.newCharacterList(text, Comparator.naturalOrder());
		assertTrue(
			CollectionExtensions.isEqualCollection(uniqueCharacters, expectedUniqueCharacters));
		encryptor = new CharacterSetEncryptor(uniqueCharacters);
		encryptedIntegerList = encryptor.encrypt(text);
		decryptor = new CharacterSetDecryptor(uniqueCharacters);
		actual = decryptor.decrypt(encryptedIntegerList);
		expected = text;
		assertEquals(actual, expected);
		// new scenario with random ordered character set...
		char[] randomDefinedOrderChars = ArrayFactory.newCharArray('f', ' ', 'p', 'E', '.', 's',
			'e', 't', 'A', 'v', 'd', 'c', 'a', 'o', 'q', 'r', 'L', 'g', 'u', 'm', 'l', 'I', 'i',
			',', 'n');
		randomDefinedOrderCharacters = ListFactory.newCharacterArrayList(null,
			randomDefinedOrderChars);
		encryptor = new CharacterSetEncryptor(randomDefinedOrderCharacters);
		encryptedIntegerList = encryptor.encrypt(text);
		decryptor = new CharacterSetDecryptor(randomDefinedOrderCharacters);
		actual = decryptor.decrypt(encryptedIntegerList);
		expected = text;
		assertEquals(actual, expected);
	}
}
