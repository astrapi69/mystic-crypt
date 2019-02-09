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
package de.alpharogroup.crypto.hex;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.nio.charset.Charset;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.StringUtils;
import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

/**
 * The unit test class for the class {@link HexExtensions}.
 */
public class HexExtensionsTest
{

	/**
	 * Test method for {@link HexExtensions#decodeHex(char[])}
	 *
	 * @throws DecoderException
	 *             is thrown if an odd number or illegal of characters is supplied
	 */
	@Test
	public void testDecodeHex() throws DecoderException
	{
		String expected;
		String actual;
		char[] actualCharArray;
		byte[] decoded;

		expected = "Secret message";
		actualCharArray = HexExtensions.encodeHex(StringUtils.getBytesUtf8(expected));
		decoded = HexExtensions.decodeHex(actualCharArray);
		actual = new String(decoded);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link HexExtensions#decodeHex(byte[])}
	 *
	 * @throws DecoderException
	 *             is thrown if an odd number or illegal of characters is supplied
	 */
	@Test
	public void testDecodeHexCharacterArray() throws DecoderException
	{
		String expected;
		String actual;
		char[] actualCharArray;
		byte[] decoded;

		expected = "Secret message";
		actualCharArray = HexExtensions.encodeHex(StringUtils.getBytesUtf8(expected));
		decoded = HexExtensions.decodeHex(actualCharArray);
		actual = HexExtensions.decodeHex(decoded);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link HexExtensions#decodeHex(String)}
	 * 
	 * @throws DecoderException
	 */
	@Test
	public void testDecodeHexString() throws DecoderException
	{
		String actual;
		String expected;
		String hexString;
		String secretMessage;

		secretMessage = "Secret message";
		hexString = "536563726574206d657373616765";
		actual = HexExtensions.decodeHex(hexString);
		expected = secretMessage;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link HexExtensions#decodeHexToString(char[])}
	 *
	 * @throws DecoderException
	 *             is thrown if an odd number or illegal of characters is supplied
	 */
	@Test
	public void testDecodeHexToString() throws DecoderException
	{
		String expected;
		String actual;
		char[] actualCharArray;

		expected = "Secret message";
		actualCharArray = HexExtensions.encodeHex(StringUtils.getBytesUtf8(expected));
		actual = HexExtensions.decodeHexToString(actualCharArray);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link HexExtensions#encodeHex(byte[])}
	 * 
	 * @throws DecoderException
	 */
	@Test
	public void testEncodeHex() throws DecoderException
	{
		String actual;
		String expected;
		String secretMessage;
		char[] actualCharArray;

		secretMessage = "Secret message";
		expected = "536563726574206d657373616765";
		actualCharArray = HexExtensions.encodeHex(StringUtils.getBytesUtf8(secretMessage));
		actual = new String(actualCharArray);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link HexExtensions#encodeHex(byte[], boolean)}
	 */
	@Test
	public void testEncodeHexBoolean()
	{
		String actual;
		String expected;
		String secretMessage;
		char[] actualCharArray;

		secretMessage = "Secret message";
		expected = "536563726574206d657373616765";
		actualCharArray = HexExtensions.encodeHex(StringUtils.getBytesUtf8(secretMessage), true);
		actual = new String(actualCharArray);
		assertEquals(expected, actual);
		actualCharArray = HexExtensions.encodeHex(StringUtils.getBytesUtf8(secretMessage), false);
		actual = new String(actualCharArray);
		assertEquals(expected.toUpperCase(), actual);
	}

	/**
	 * Test method for {@link HexExtensions#encodeHex(String, Charset, boolean)}
	 */
	@Test
	public void testEncodeHexStringCharsetBoolean()
	{
		String actual;
		String expected;
		String hexString;
		String secretMessage;

		secretMessage = "Secret message";
		hexString = "536563726574206d657373616765";
		actual = HexExtensions.encodeHex(secretMessage, Charset.forName("UTF-8"), true);
		expected = hexString;
		assertEquals(expected, actual);

		secretMessage = "Secret message";
		hexString = "536563726574206D657373616765";
		actual = HexExtensions.encodeHex(secretMessage, Charset.forName("UTF-8"), false);
		expected = hexString;
		assertEquals(expected, actual);

		secretMessage = "Secret message";
		hexString = "536563726574206D657373616765";
		actual = HexExtensions.encodeHex(secretMessage, null, false);
		expected = hexString;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link HexExtensions#encodeHex(String)}
	 */
	@Test
	public void testEncodeString()
	{
		String actual;
		String expected;
		String secretMessage;
		char[] actualCharArray;

		secretMessage = "Secret message";
		expected = "536563726574206d657373616765";
		actualCharArray = HexExtensions.encodeHex(secretMessage);
		actual = new String(actualCharArray);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link HexExtensions#toHex(int)}
	 */
	@Test
	public void testToHex()
	{
		char actual;

		actual = HexExtensions.toHex(5);
		assertTrue(actual == '5');
		actual = HexExtensions.toHex(10);
		assertTrue(actual == 'A');
	}

	/**
	 * Test method for {@link HexExtensions} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(HexExtensions.class);
	}

}
