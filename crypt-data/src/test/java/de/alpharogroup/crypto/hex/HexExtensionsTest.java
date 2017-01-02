package de.alpharogroup.crypto.hex;

import static org.junit.Assert.assertEquals;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.StringUtils;
import org.testng.annotations.Test;

/**
 * Test class for the class {@link HexExtensions}.
 */
public class HexExtensionsTest {

	/**
	 * Test method for {@link HexExtensions#decodeHex(char[])}
	 *
	 * @throws DecoderException
	 *             is thrown if an odd number or illegal of characters is supplied
	 */
	@Test
	public void testDecodeHex() throws DecoderException
	{
		final String expected = "Secret message";
		final char[] actualCharArray = HexExtensions.encodeHex(StringUtils.getBytesUtf8(expected));
		final byte[] decoded = HexExtensions.decodeHex(actualCharArray);
		final String actual = new String(decoded);
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
		final String expected = "Secret message";
		final char[] actualCharArray = HexExtensions.encodeHex(StringUtils.getBytesUtf8(expected));
		final byte[] decoded = HexExtensions.decodeHex(actualCharArray);
		final String actual = HexExtensions.decodeHex(decoded);
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
		final String expected = "Secret message";
		final char[] actualCharArray = HexExtensions.encodeHex(StringUtils.getBytesUtf8(expected));
		final String actual = HexExtensions.decodeHexToString(actualCharArray);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link HexExtensions#encodeHex(byte[])}
	 */
	@Test
	public void testEncodeHex()
	{
		final String secretMessage = "Secret message";
		final String expected = "536563726574206d657373616765";
		final char[] actualCharArray = HexExtensions.encodeHex(StringUtils.getBytesUtf8(secretMessage));
		final String actual = new String(actualCharArray);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link HexExtensions#encodeHex(byte[], boolean)}
	 */
	@Test
	public void testEncodeHexBoolean()
	{
		final String secretMessage = "Secret message";
		final String expected = "536563726574206d657373616765";
		char[] actualCharArray = HexExtensions.encodeHex(StringUtils.getBytesUtf8(secretMessage), true);
		String actual = new String(actualCharArray);
		assertEquals(expected, actual);
		actualCharArray = HexExtensions.encodeHex(StringUtils.getBytesUtf8(secretMessage), false);
		actual = new String(actualCharArray);
		assertEquals(expected.toUpperCase(), actual);
	}

	/**
	 * Test method for {@link HexExtensions#encodeHex(String)}
	 */
	@Test
	public void testEncodeString()
	{
		final String secretMessage = "Secret message";
		final String expected = "536563726574206d657373616765";
		final char[] actualCharArray = HexExtensions.encodeHex(secretMessage);
		final String actual = new String(actualCharArray);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link HexExtensions#toHex(int)}
	 */
	@Test
	public void testToHex()
	{
		char actual = HexExtensions.toHex(5);
		org.junit.Assert.assertTrue(actual == '5');
		actual = HexExtensions.toHex(10);
		org.junit.Assert.assertTrue(actual == 'A');
	}


}
