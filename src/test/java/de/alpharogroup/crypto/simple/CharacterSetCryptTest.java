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
package de.alpharogroup.crypto.simple;

import static org.testng.AssertJUnit.assertEquals;

import java.util.Comparator;
import java.util.List;

import org.testng.annotations.Test;

import de.alpharogroup.collections.list.ListExtensions;
import de.alpharogroup.collections.list.ListFactory;

/**
 * The unit test class for the class {@link CharacterSetCrypt}
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class CharacterSetCryptTest {

	/**
	 * Test method for test the method
	 * {@link CharacterSetCrypt#newCharacterList(String)}
	 */
	@Test
	public void testNewCharacterList() {
		List<Character> actual;
		List<Character> expected;

		String text = "Lorem ipsum dolor sit amet, sea consul verterem perfecto id. Alii prompta electram te nec, at minimum copiosae quo. Eos iudico nominati oportere ei, usu at dicta legendos. In nostrum insolens disputando pro, iusto equidem ius id.";
		actual = CharacterSetCrypt.newCharacterList(text);

		expected = ListFactory.newArrayList(Character.valueOf((char) 0x20), ',', '.', 'A', 'E', 'I', 'L', 'a', 'c', 'd',
				'e', 'f', 'g', 'i', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v');
		assertEquals(actual, expected);
	}

	/**
	 * Test method for test the method
	 * {@link CharacterSetCrypt#newCharacterList(String, java.util.Comparator)}
	 */
	@Test
	public void testNewCharacterListWithComparator() {
		List<Character> actual;
		List<Character> expected;

		String text = "Lorem ipsum dolor sit amet, sea consul verterem perfecto id. Alii prompta electram te nec, at minimum copiosae quo. Eos iudico nominati oportere ei, usu at dicta legendos. In nostrum insolens disputando pro, iusto equidem ius id.";
		actual = CharacterSetCrypt.newCharacterList(text, Comparator.<Character>naturalOrder().reversed());

		expected = ListExtensions
				.revertOrder(ListFactory.newArrayList(Character.valueOf((char) 0x20), ',', '.', 'A', 'E', 'I', 'L', 'a',
						'c', 'd', 'e', 'f', 'g', 'i', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v'));
		assertEquals(actual, expected);
	}

	/**
	 * Test method for test the method
	 * {@link CharacterSetCrypt#toIndexList(String, List)}
	 */
	@Test
	public void testToIndexList() {
		List<Integer> actual;
		List<Integer> expected;
		String text = "Lorem ipsum dolor sit amet, sea consul verterem perfecto id. Alii prompta electram te nec, at minimum copiosae quo. Eos iudico nominati oportere ei, usu at dicta legendos. In nostrum insolens disputando pro, iusto equidem ius id.";
		List<Character> uniqueCharacters = CharacterSetCrypt.newCharacterList(text);
		actual = CharacterSetCrypt.toIndexList(text, uniqueCharacters);
		System.out.println(actual);
		expected = ListFactory.newArrayList(6, 17, 20, 10, 15, 0, 13, 18, 21, 23, 15, 0, 9, 17, 14, 17, 20, 0, 21, 13,
				22, 0, 7, 15, 10, 22, 1, 0, 21, 10, 7, 0, 8, 17, 16, 21, 23, 14, 0, 24, 10, 20, 22, 10, 20, 10, 15, 0,
				18, 10, 20, 11, 10, 8, 22, 17, 0, 13, 9, 2, 0, 3, 14, 13, 13, 0, 18, 20, 17, 15, 18, 22, 7, 0, 10, 14,
				10, 8, 22, 20, 7, 15, 0, 22, 10, 0, 16, 10, 8, 1, 0, 7, 22, 0, 15, 13, 16, 13, 15, 23, 15, 0, 8, 17, 18,
				13, 17, 21, 7, 10, 0, 19, 23, 17, 2, 0, 4, 17, 21, 0, 13, 23, 9, 13, 8, 17, 0, 16, 17, 15, 13, 16, 7,
				22, 13, 0, 17, 18, 17, 20, 22, 10, 20, 10, 0, 10, 13, 1, 0, 23, 21, 23, 0, 7, 22, 0, 9, 13, 8, 22, 7, 0,
				14, 10, 12, 10, 16, 9, 17, 21, 2, 0, 5, 16, 0, 16, 17, 21, 22, 20, 23, 15, 0, 13, 16, 21, 17, 14, 10,
				16, 21, 0, 9, 13, 21, 18, 23, 22, 7, 16, 9, 17, 0, 18, 20, 17, 1, 0, 13, 23, 21, 22, 17, 0, 10, 19, 23,
				13, 9, 10, 15, 0, 13, 23, 21, 0, 13, 9, 2);
		assertEquals(actual, expected);
	}

	/**
	 * Test method for test the method {@link CharacterSetCrypt#toText(List, List)}
	 * <br>
	 * <br>
	 * This test method provides a full example of how this en- decryption algorithm
	 * works
	 */
	@Test
	public void testToText() {
		String actual;
		String expected;
		String text = "Lorem ipsum dolor sit amet, sea consul verterem perfecto id. Alii prompta electram te nec, at minimum copiosae quo. Eos iudico nominati oportere ei, usu at dicta legendos. In nostrum insolens disputando pro, iusto equidem ius id.";
		List<Character> uniqueCharacters = CharacterSetCrypt.newCharacterList(text);
		List<Integer> indexesList = CharacterSetCrypt.toIndexList(text, uniqueCharacters);
		actual = CharacterSetCrypt.toText(indexesList, uniqueCharacters);
		expected = text;
		assertEquals(actual, expected);
	}

	/**
	 * Test method for test utf-8 characters in a loop
	 */
	@Test
	public void testUtf8Characters() {
		int count = 1;
		for (int i = 0; i < 65536; i++) {
			char[] chars = Character.toChars(i);
			char currentChar = chars[0];
			Character c = Character.valueOf(currentChar);
			if (Character.isDefined(i) && Character.isAlphabetic(i) && !Character.isIdeographic(i)
					&& !Character.isISOControl(i) && Character.getType(currentChar) != 5) {

				System.out.println(count + ":" + i + "=    " + c + "    ::" + Character.getType(currentChar));
				count++;
			}
		}
	}

}
