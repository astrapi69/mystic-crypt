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
package io.github.astrapi69.mystic.crypt.decorator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvFileSource;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.data.model.CryptObjectDecorator;

/**
 * The unit test class for the class {@link CryptObjectDecoratorExtensions}
 */
public class CryptObjectDecoratorExtensionsTest
{

	/**
	 * Test method for
	 * {@link CryptObjectDecoratorExtensions#decorateWithStringDecorator(String, CryptObjectDecorator)}.
	 *
	 * @param input
	 *            the input string to be decorated
	 * @param prefix
	 *            the prefix for decoration
	 * @param suffix
	 *            the suffix for decoration
	 * @param expected
	 *            the expected result after decoration
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/decorateStringTest.csv", numLinesToSkip = 1)
	void testDecorateWithStringDecorator(String input, String prefix, String suffix,
		String expected)
	{
		CryptObjectDecorator<String> decorator;

		decorator = CryptObjectDecorator.<String> builder().prefix(prefix).suffix(suffix).build();
		String result = CryptObjectDecoratorExtensions.decorateWithStringDecorator(input,
			decorator);
		assertEquals(expected, result);
	}

	/**
	 * Test method for
	 * {@link CryptObjectDecoratorExtensions#undecorateWithStringDecorator(String, CryptObjectDecorator)}.
	 *
	 * @param input
	 *            the input string to be undecorated
	 * @param prefix
	 *            the prefix for undecoration
	 * @param suffix
	 *            the suffix for undecoration
	 * @param expected
	 *            the expected result after undecoration
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/undecorateStringTest.csv", numLinesToSkip = 1)
	void testUndecorateWithStringDecorator(String input, String prefix, String suffix,
		String expected)
	{
		CryptObjectDecorator<String> decorator;

		decorator = CryptObjectDecorator.<String> builder().prefix(prefix).suffix(suffix).build();
		String result = CryptObjectDecoratorExtensions.undecorateWithStringDecorator(input,
			decorator);
		assertEquals(expected, result);
	}

	/**
	 * Test method for
	 * {@link CryptObjectDecoratorExtensions#decorateWithBytearrayDecorator(String, CryptObjectDecorator, Charset)}.
	 *
	 * @param input
	 *            the input string to be decorated
	 * @param prefix
	 *            the prefix for decoration
	 * @param suffix
	 *            the suffix for decoration
	 * @param expected
	 *            the expected result after decoration
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/decorateBytearrayTest.csv", numLinesToSkip = 1)
	void testDecorateWithBytearrayDecorator(String input, String prefix, String suffix,
		String expected)
	{

		CryptObjectDecorator<byte[]> decorator;

		decorator = CryptObjectDecorator.<byte[]> builder()
			.prefix(prefix.getBytes(StandardCharsets.UTF_8))
			.suffix(suffix.getBytes(StandardCharsets.UTF_8)).build();
		String result = CryptObjectDecoratorExtensions.decorateWithBytearrayDecorator(input,
			decorator, StandardCharsets.UTF_8);
		assertEquals(expected, result);
	}

	/**
	 * Test method for
	 * {@link CryptObjectDecoratorExtensions#undecorateWithBytearrayDecorator(String, CryptObjectDecorator)}.
	 *
	 * @param input
	 *            the input string to be undecorated
	 * @param prefix
	 *            the prefix for undecoration
	 * @param suffix
	 *            the suffix for undecoration
	 * @param expected
	 *            the expected result after undecoration
	 */
	@ParameterizedTest
	@CsvFileSource(resources = "/undecorateBytearrayTest.csv", numLinesToSkip = 1)
	void testUndecorateWithBytearrayDecorator(String input, String prefix, String suffix,
		String expected)
	{
		CryptObjectDecorator<byte[]> decorator;

		decorator = CryptObjectDecorator.<byte[]> builder()
			.prefix(prefix.getBytes(StandardCharsets.UTF_8))
			.suffix(suffix.getBytes(StandardCharsets.UTF_8)).build();
		String result = CryptObjectDecoratorExtensions.undecorateWithBytearrayDecorator(input,
			decorator);
		assertEquals(expected, result);
	}

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
	 * Test method for the decoration of an crypt object with {@link CryptObjectDecorator}
	 */
	@Test
	public void testDecorateWithCharacterDecorator()
	{
		String actual;
		String expected;
		String toEncrypt;
		CryptObjectDecorator<Character> decorator;

		toEncrypt = "mile";
		decorator = CryptObjectDecorator.<Character> builder().prefix('s').suffix('s').build();

		actual = CryptObjectDecoratorExtensions.decorateWithCharacterDecorator(toEncrypt,
			decorator);
		expected = "smiles";
		assertEquals(actual, expected);
	}

	/**
	 * Test method for the decoration of an crypt object with {@link CryptObjectDecorator}
	 */
	@Test
	public void testDecorateWithStringDecorator()
	{
		String actual;
		String expected;
		String toEncrypt;
		CryptObjectDecorator<String> decorator;

		toEncrypt = "mile";
		decorator = CryptObjectDecorator.<String> builder().prefix("s").suffix("s").build();

		actual = CryptObjectDecoratorExtensions.decorateWithStringDecorator(toEncrypt, decorator);
		expected = "smiles";
		assertEquals(actual, expected);

		// new scenario ...
		decorator = CryptObjectDecorator.<String> builder().prefix("").suffix("s").build();

		actual = CryptObjectDecoratorExtensions.decorateWithStringDecorator(toEncrypt, decorator);
		expected = "miles";
		assertEquals(actual, expected);

		// new scenario ...
		decorator = CryptObjectDecorator.<String> builder().prefix("s").suffix("").build();

		actual = CryptObjectDecoratorExtensions.decorateWithStringDecorator(toEncrypt, decorator);
		expected = "smile";
		assertEquals(actual, expected);
		// new scenario ...
		decorator = CryptObjectDecorator.<String> builder().prefix("").suffix("").build();

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
	 * Test method for undecorate an crypt object with {@link CryptObjectDecorator}
	 */
	@Test
	public void testUndecorateWithCharacterDecorator()
	{
		String actual;
		String expected;
		String toEncrypt;
		CryptObjectDecorator<Character> decorator;

		toEncrypt = "smiles";
		decorator = CryptObjectDecorator.<Character> builder().prefix('s').suffix('s').build();

		actual = CryptObjectDecoratorExtensions.undecorateWithCharacterDecorator(toEncrypt,
			decorator);
		expected = "mile";
		assertEquals(actual, expected);
	}

	/**
	 * Test method for undecorate an crypt object with {@link CryptObjectDecorator}
	 */
	@Test
	public void testUndecorateWithStringDecorator()
	{
		String actual;
		String expected;
		String toEncrypt;
		CryptObjectDecorator<String> decorator;

		toEncrypt = "smiles";
		decorator = CryptObjectDecorator.<String> builder().prefix("s").suffix("s").build();

		actual = CryptObjectDecoratorExtensions.undecorateWithStringDecorator(toEncrypt, decorator);
		expected = "mile";
		assertEquals(actual, expected);

		// new scenario ...
		decorator = CryptObjectDecorator.<String> builder().prefix("").suffix("s").build();

		actual = CryptObjectDecoratorExtensions.undecorateWithStringDecorator(toEncrypt, decorator);
		expected = "smile";
		assertEquals(actual, expected);

		// new scenario ...
		decorator = CryptObjectDecorator.<String> builder().prefix("s").suffix("").build();

		actual = CryptObjectDecoratorExtensions.undecorateWithStringDecorator(toEncrypt, decorator);
		expected = "miles";
		assertEquals(actual, expected);
		// new scenario ...
		decorator = CryptObjectDecorator.<String> builder().prefix("").suffix("").build();

		actual = CryptObjectDecoratorExtensions.undecorateWithStringDecorator(toEncrypt, decorator);
		expected = "smiles";
		assertEquals(actual, expected);
	}


	/**
	 * A scenario for undecorating with a character decorator
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param input
	 *            the decorated input
	 * @param prefix
	 *            the prefix character
	 * @param suffix
	 *            the suffix character
	 * @param expected
	 *            the expected undecorated result
	 */
	record CharacterUndecorateCase(String description, String input, char prefix, char suffix,
		String expected) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static Stream<CharacterUndecorateCase> characterUndecorateCases()
	{
		return Stream.of(new CharacterUndecorateCase("prefix and suffix", "[abc]", '[', ']', "abc"),
			new CharacterUndecorateCase("only the prefix", "[abc", '[', ']', "abc"),
			new CharacterUndecorateCase("only the suffix", "abc]", '[', ']', "abc"),
			new CharacterUndecorateCase("neither prefix nor suffix", "abc", '[', ']', "abc"),
			new CharacterUndecorateCase("same character as prefix and suffix", "sabcs", 's', 's',
				"abc"));
	}

	/**
	 * Test method for
	 * {@link CryptObjectDecoratorExtensions#undecorateWithCharacterDecorator(String, CryptObjectDecorator)}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("characterUndecorateCases")
	void undecorateWithCharacterDecorator_removesOnlyThePresentDecorations(
		final CharacterUndecorateCase testCase)
	{
		CryptObjectDecorator<Character> characterDecorator = CryptObjectDecorator
			.<Character> builder().prefix(testCase.prefix()).suffix(testCase.suffix()).build();

		assertEquals(testCase.expected(), CryptObjectDecoratorExtensions
			.undecorateWithCharacterDecorator(testCase.input(), characterDecorator));
	}

	/**
	 * A scenario for undecorating with a byte array decorator
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param input
	 *            the decorated input
	 * @param prefix
	 *            the prefix
	 * @param suffix
	 *            the suffix
	 * @param expected
	 *            the expected undecorated result
	 */
	record ByteArrayUndecorateCase(String description, String input, String prefix, String suffix,
		String expected) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static Stream<ByteArrayUndecorateCase> byteArrayUndecorateCases()
	{
		return Stream.of(
			new ByteArrayUndecorateCase("prefix and suffix", "<<abc>>", "<<", ">>", "abc"),
			new ByteArrayUndecorateCase("only the suffix", "abc>>", "<<", ">>", "abc"),
			new ByteArrayUndecorateCase("suffix that only partially matches", "abc=>", "<<", ">>",
				"abc=>"),
			new ByteArrayUndecorateCase("suffix longer than the input", "a", "<<", ">>>>", "a"),
			new ByteArrayUndecorateCase("empty suffix is never removed", "abc", "<<", "", "abc"),
			new ByteArrayUndecorateCase("neither prefix nor suffix", "abc", "<<", ">>", "abc"),
			new ByteArrayUndecorateCase(
				"prefix bytes that appear elsewhere are removed from the input once", "a<b<c", "<<",
				">>", "abc"),
			new ByteArrayUndecorateCase("a doubled prefix is removed completely", "<<<<abc", "<<",
				">>", "abc"),
			new ByteArrayUndecorateCase("a prefix that only partially matches is kept", "<=abc",
				"<<", ">>", "=abc"));
	}

	/**
	 * Test method for
	 * {@link CryptObjectDecoratorExtensions#undecorateWithBytearrayDecorator(String, CryptObjectDecorator)}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("byteArrayUndecorateCases")
	void undecorateWithBytearrayDecorator_removesOnlyThePresentDecorations(
		final ByteArrayUndecorateCase testCase)
	{
		CryptObjectDecorator<byte[]> byteArrayDecorator = CryptObjectDecorator.<byte[]> builder()
			.prefix(testCase.prefix().getBytes(StandardCharsets.UTF_8))
			.suffix(testCase.suffix().getBytes(StandardCharsets.UTF_8)).build();

		assertEquals(testCase.expected(), CryptObjectDecoratorExtensions
			.undecorateWithBytearrayDecorator(testCase.input(), byteArrayDecorator));
	}

	/**
	 * Test method for
	 * {@link CryptObjectDecoratorExtensions#undecorateWithBytearrayDecorator(String, CryptObjectDecorator)}
	 * with an input that is shorter than the suffix but matches its tail
	 * <p>
	 * Note: this test documents a known defect. The suffix check runs out of input bytes before it
	 * runs out of suffix bytes and answers true, so the removal of the suffix tries to copy a
	 * negative number of bytes.
	 */
	@Test
	void undecorateWithBytearrayDecorator_currentlyFailsForAnInputShorterThanAMatchingSuffix()
	{
		CryptObjectDecorator<byte[]> byteArrayDecorator = CryptObjectDecorator.<byte[]> builder()
			.prefix(new byte[0]).suffix(">>".getBytes(StandardCharsets.UTF_8)).build();

		assertThrows(NegativeArraySizeException.class, () -> CryptObjectDecoratorExtensions
			.undecorateWithBytearrayDecorator(">", byteArrayDecorator));
	}

	/**
	 * Test method for
	 * {@link CryptObjectDecoratorExtensions#decorateFile(java.io.File, CryptObjectDecorator)}: the
	 * file content must be wrapped with the decorator's prefix and suffix. Guards against a mutant
	 * that returns an empty string.
	 *
	 * @throws java.io.IOException
	 *             if an I/O error occurs
	 */
	@Test
	void decorateFile_wrapsTheFileContentWithThePrefixAndSuffix() throws java.io.IOException
	{
		java.io.File file = java.io.File.createTempFile("decorate-file-test", ".txt");
		file.deleteOnExit();
		java.nio.file.Files.write(file.toPath(), "payload".getBytes(StandardCharsets.UTF_8));

		CryptObjectDecorator<String> decorator = CryptObjectDecorator.<String> builder()
			.prefix("<<").suffix(">>").build();

		String result = CryptObjectDecoratorExtensions.decorateFile(file, decorator);
		assertEquals("<<payload>>", result);
	}
}
