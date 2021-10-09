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

import java.nio.charset.StandardCharsets;
import java.util.List;

import io.github.astrapi69.collections.list.ListFactory;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import io.github.astrapi69.collections.array.ArrayFactory;

/**
 * The unit test class for the class {@link CharacterSetEncryptor}
 */
public class CharacterSetEncryptorTest
{

	/**
	 * Test method for the {@link CharacterSetEncryptor#encrypt(String)}  method
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public void testEncrypt() throws Exception
	{

		List<Integer> actual;
		List<Integer> expected;
		String text = "Lorem ipsum dolor sit amet, sea consul verterem perfecto id. Alii prompta electram te nec, at minimum copiosae quo. Eos iudico nominati oportere ei, usu at dicta legendos. In nostrum insolens disputando pro, iusto equidem ius id.";
		List<Character> uniqueCharacters = CharacterSetCrypt.newCharacterList(text);
		CharacterSetEncryptor encryptor = new CharacterSetEncryptor(uniqueCharacters);
		actual = encryptor.encrypt(text);
		System.out.println(actual);
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
		AssertJUnit.assertEquals(actual, expected);
	}
}
