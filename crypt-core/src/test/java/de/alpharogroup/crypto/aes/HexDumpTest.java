/**
 * Copyright (C) 2007 Asterios Raptis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.alpharogroup.crypto.aes;

import static org.junit.Assert.assertEquals;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.StringUtils;
import org.junit.Test;

/**
 * The Class HexDumpTest.
 */
public class HexDumpTest
{

	/**
	 * Test method for {@link de.alpharogroup.crypto.aes.HexDump#decodeHex(char[])}
	 *
	 * @throws DecoderException
	 *             the decoder exception
	 */
	@Test
	public void testDecodeHex() throws DecoderException
	{
		final String expected = "Secret message";
		final char[] actualCharArray = HexDump.encodeHex(StringUtils.getBytesUtf8(expected));
		final byte[] decoded = HexDump.decodeHex(actualCharArray);
		final String actual = new String(decoded);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link de.alpharogroup.crypto.aes.HexDump#decodeHex(byte[])}
	 *
	 * @throws DecoderException
	 *             the decoder exception
	 */
	@Test
	public void testDecodeHexCharacterArray() throws DecoderException
	{
		final String expected = "Secret message";
		final char[] actualCharArray = HexDump.encodeHex(StringUtils.getBytesUtf8(expected));
		final byte[] decoded = HexDump.decodeHex(actualCharArray);
		final String actual = HexDump.decodeHex(decoded);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link de.alpharogroup.crypto.aes.HexDump#decodeHexToString(char[])}
	 *
	 * @throws DecoderException
	 *             the decoder exception
	 */
	@Test
	public void testDecodeHexToString() throws DecoderException
	{
		final String expected = "Secret message";
		final char[] actualCharArray = HexDump.encodeHex(StringUtils.getBytesUtf8(expected));
		final String actual = HexDump.decodeHexToString(actualCharArray);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link de.alpharogroup.crypto.aes.HexDump#encodeHex(byte[])}
	 */
	@Test
	public void testEncodeHex()
	{
		final String secretMessage = "Secret message";
		final String expected = "536563726574206d657373616765";
		final char[] actualCharArray = HexDump.encodeHex(StringUtils.getBytesUtf8(secretMessage));
		final String actual = new String(actualCharArray);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link de.alpharogroup.crypto.aes.HexDump#encodeHex(byte[], boolean)}
	 */
	@Test
	public void testEncodeHexBoolean()
	{
		final String secretMessage = "Secret message";
		final String expected = "536563726574206d657373616765";
		char[] actualCharArray = HexDump.encodeHex(StringUtils.getBytesUtf8(secretMessage), true);
		String actual = new String(actualCharArray);
		assertEquals(expected, actual);
		actualCharArray = HexDump.encodeHex(StringUtils.getBytesUtf8(secretMessage), false);
		actual = new String(actualCharArray);
		assertEquals(expected.toUpperCase(), actual);
	}

	/**
	 * Test method for {@link de.alpharogroup.crypto.aes.HexDump#encodeHex(String)}
	 */
	@Test
	public void testEncodeString()
	{
		final String secretMessage = "Secret message";
		final String expected = "536563726574206d657373616765";
		final char[] actualCharArray = HexDump.encodeHex(secretMessage);
		final String actual = new String(actualCharArray);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link de.alpharogroup.crypto.aes.HexDump#toHex(int)}
	 */
	@Test
	public void testToHex()
	{
		char actual = HexDump.toHex(5);
		org.junit.Assert.assertTrue(actual == '5');
		actual = HexDump.toHex(10);
		org.junit.Assert.assertTrue(actual == 'A');
	}

}
