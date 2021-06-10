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
package de.alpharogroup.crypto.decorator;

import static org.testng.Assert.assertEquals;

import java.nio.charset.Charset;

import org.testng.annotations.Test;

import io.github.astrapi69.crypto.model.CharacterDecorator;
import io.github.astrapi69.crypto.model.CryptObjectDecorator;
import io.github.astrapi69.crypto.model.StringDecorator;

/**
 * The unit test class for the class {@link CryptObjectDecoratorExtensions}
 */
public class CryptObjectDecoratorExtensionsTest
{

	/**
	 * Test method for the decoration of an crypt object with {@link CryptObjectDecorator} with byte
	 * array as prefix and suffix
	 */
	@Test
	public void testDecorateWithByteArrayDecorator()
	{
		String actual;
		String expected;
		String toEncrypt;
		CryptObjectDecorator<byte[]> decorator;
		Charset utf8 = Charset.forName("UTF-8");

		toEncrypt = "mile";
		decorator = CryptObjectDecorator.<byte[]> builder().prefix("s".getBytes(utf8))
			.suffix("s".getBytes(utf8)).build();

		actual = CryptObjectDecoratorExtensions.decorateWithBytearrayDecorator(toEncrypt, decorator,
			utf8);
		expected = "smiles";
		assertEquals(actual, expected);

		// new scenario ...
		decorator = CryptObjectDecorator.<byte[]> builder().prefix("".getBytes(utf8))
			.suffix("s".getBytes(utf8)).build();

		actual = CryptObjectDecoratorExtensions.decorateWithBytearrayDecorator(toEncrypt, decorator,
			utf8);
		expected = "miles";
		assertEquals(actual, expected);

		// new scenario ...
		decorator = CryptObjectDecorator.<byte[]> builder().prefix("s".getBytes(utf8))
			.suffix("".getBytes(utf8)).build();

		actual = CryptObjectDecoratorExtensions.decorateWithBytearrayDecorator(toEncrypt, decorator,
			utf8);
		expected = "smile";
		assertEquals(actual, expected);
		// new scenario ...
		decorator = CryptObjectDecorator.<byte[]> builder().prefix("".getBytes(utf8))
			.suffix("".getBytes(utf8)).build();

		actual = CryptObjectDecoratorExtensions.decorateWithBytearrayDecorator(toEncrypt, decorator,
			utf8);
		expected = "mile";
		assertEquals(actual, expected);
	}

	/**
	 * Test method for the decoration of an crypt object with {@link CharacterDecorator}
	 */
	@Test
	public void testDecorateWithCharacterDecorator()
	{
		String actual;
		String expected;
		String toEncrypt;
		CharacterDecorator decorator;

		toEncrypt = "mile";
		decorator = CharacterDecorator.builder().prefix('s').suffix('s').build();

		actual = CryptObjectDecoratorExtensions.decorateWithCharacterDecorator(toEncrypt,
			decorator);
		expected = "smiles";
		assertEquals(actual, expected);
	}

	/**
	 * Test method for the decoration of an crypt object with {@link StringDecorator}
	 */
	@Test
	public void testDecorateWithStringDecorator()
	{
		String actual;
		String expected;
		String toEncrypt;
		StringDecorator decorator;

		toEncrypt = "mile";
		decorator = StringDecorator.builder().prefix("s").suffix("s").build();

		actual = CryptObjectDecoratorExtensions.decorateWithStringDecorator(toEncrypt, decorator);
		expected = "smiles";
		assertEquals(actual, expected);

		// new scenario ...
		decorator = StringDecorator.builder().prefix("").suffix("s").build();

		actual = CryptObjectDecoratorExtensions.decorateWithStringDecorator(toEncrypt, decorator);
		expected = "miles";
		assertEquals(actual, expected);

		// new scenario ...
		decorator = StringDecorator.builder().prefix("s").suffix("").build();

		actual = CryptObjectDecoratorExtensions.decorateWithStringDecorator(toEncrypt, decorator);
		expected = "smile";
		assertEquals(actual, expected);
		// new scenario ...
		decorator = StringDecorator.builder().prefix("").suffix("").build();

		actual = CryptObjectDecoratorExtensions.decorateWithStringDecorator(toEncrypt, decorator);
		expected = "mile";
		assertEquals(actual, expected);
	}

	/**
	 * Test method for undecorate an crypt object with {@link CryptObjectDecorator} with byte array
	 * as prefix and suffix
	 */
	@Test
	public void testUndecorateWithByteArrayDecorator()
	{
		String actual;
		String expected;
		String toEncrypt;
		CryptObjectDecorator<byte[]> decorator;

		toEncrypt = "smiles";
		decorator = CryptObjectDecorator.<byte[]> builder().prefix("s".getBytes())
			.suffix("s".getBytes()).build();

		actual = CryptObjectDecoratorExtensions.undecorateWithBytearrayDecorator(toEncrypt,
			decorator);
		expected = "mile";
		assertEquals(actual, expected);

		// new scenario ...
		decorator = CryptObjectDecorator.<byte[]> builder().prefix("".getBytes())
			.suffix("s".getBytes()).build();

		actual = CryptObjectDecoratorExtensions.undecorateWithBytearrayDecorator(toEncrypt,
			decorator);
		expected = "smile";
		assertEquals(actual, expected);

		// new scenario ...
		decorator = CryptObjectDecorator.<byte[]> builder().prefix("s".getBytes())
			.suffix("".getBytes()).build();

		actual = CryptObjectDecoratorExtensions.undecorateWithBytearrayDecorator(toEncrypt,
			decorator);
		expected = "miles";
		assertEquals(actual, expected);
		// new scenario ...
		decorator = CryptObjectDecorator.<byte[]> builder().prefix("".getBytes())
			.suffix("".getBytes()).build();

		actual = CryptObjectDecoratorExtensions.undecorateWithBytearrayDecorator(toEncrypt,
			decorator);
		expected = "smiles";
		assertEquals(actual, expected);
	}

	/**
	 * Test method for undecorate an crypt object with {@link CharacterDecorator}
	 */
	@Test
	public void testUndecorateWithCharacterDecorator()
	{
		String actual;
		String expected;
		String toEncrypt;
		CharacterDecorator decorator;

		toEncrypt = "smiles";
		decorator = CharacterDecorator.builder().prefix('s').suffix('s').build();

		actual = CryptObjectDecoratorExtensions.undecorateWithCharacterDecorator(toEncrypt,
			decorator);
		expected = "mile";
		assertEquals(actual, expected);
	}

	/**
	 * Test method for undecorate an crypt object with {@link StringDecorator}
	 */
	@Test
	public void testUndecorateWithStringDecorator()
	{
		String actual;
		String expected;
		String toEncrypt;
		StringDecorator decorator;

		toEncrypt = "smiles";
		decorator = StringDecorator.builder().prefix("s").suffix("s").build();

		actual = CryptObjectDecoratorExtensions.undecorateWithStringDecorator(toEncrypt, decorator);
		expected = "mile";
		assertEquals(actual, expected);

		// new scenario ...
		decorator = StringDecorator.builder().prefix("").suffix("s").build();

		actual = CryptObjectDecoratorExtensions.undecorateWithStringDecorator(toEncrypt, decorator);
		expected = "smile";
		assertEquals(actual, expected);

		// new scenario ...
		decorator = StringDecorator.builder().prefix("s").suffix("").build();

		actual = CryptObjectDecoratorExtensions.undecorateWithStringDecorator(toEncrypt, decorator);
		expected = "miles";
		assertEquals(actual, expected);
		// new scenario ...
		decorator = StringDecorator.builder().prefix("").suffix("").build();

		actual = CryptObjectDecoratorExtensions.undecorateWithStringDecorator(toEncrypt, decorator);
		expected = "smiles";
		assertEquals(actual, expected);
	}

}
