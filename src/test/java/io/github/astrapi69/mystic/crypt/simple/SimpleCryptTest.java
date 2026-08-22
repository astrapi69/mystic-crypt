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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

/**
 * The unit test class for the class {@link SimpleCrypt}
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class SimpleCryptTest
{

	/**
	 * Test method for test the method {@link SimpleCrypt#oneTimePadCrypt(byte[], byte[])}
	 */
	@Test
	public void testOneTimePad()
	{
		byte[] encoded;
		byte[] decoded;
		byte[] secret = "top-secret".getBytes();
		byte[] key = new byte[secret.length];

		encoded = SimpleCrypt.oneTimePadCrypt(key, secret);
		decoded = SimpleCrypt.oneTimePadCrypt(key, encoded);

		assertTrue(Arrays.equals(secret, decoded));
	}

	/**
	 * Test method for {@link SimpleCrypt#oneTimePadCrypt(byte[], byte[])} where the message is
	 * longer than the key. In that case the key index wraps around via
	 * {@code message.length % (simpleKey.length - 1)}; asserting the exact encoded bytes pins that
	 * arithmetic so a mutant that turns the subtraction into an addition is caught (a plain
	 * round-trip cannot catch it because the XOR is symmetric).
	 */
	@Test
	public void testOneTimePadWithMessageLongerThanKey()
	{
		byte[] key = { 10, 20, 30, 40 };
		byte[] message = { 1, 2, 3, 4, 5, 6 };

		byte[] encoded = SimpleCrypt.oneTimePadCrypt(key, message);

		// independently compute the expected output with the documented key-index formula
		byte[] expected = new byte[message.length];
		for (int index = 0; index < message.length; index++)
		{
			int keyIndex = index;
			if (index >= key.length)
			{
				keyIndex = message.length % (key.length - 1);
			}
			expected[index] = (byte)(message[index] ^ key[keyIndex]);
		}
		assertEquals(Arrays.toString(expected), Arrays.toString(encoded));
		// index 4 and 5 use keyIndex = 6 % 3 = 0 (key[0] == 10); an addition mutant would use
		// 6 % 5 = 1 (key[1] == 20), producing a different byte
		assertEquals((byte)(message[4] ^ key[0]), encoded[4]);
		assertEquals((byte)(message[5] ^ key[0]), encoded[5]);

		// round-trip must still recover the message
		assertTrue(Arrays.equals(message, SimpleCrypt.oneTimePadCrypt(key, encoded)));
	}

	/**
	 * Test method for test the method {@link SimpleCrypt#encode(String)} and
	 * {@link SimpleCrypt#decode(String)}
	 */
	@Test
	public void testSimpleCrypt01()
	{
		String actual;
		String expected;
		String testString;
		String encrypted;

		testString = "top secret";
		expected = testString;
		encrypted = SimpleCrypt.encode(testString);
		actual = SimpleCrypt.decode(encrypted);
		assertEquals(actual, expected);
	}

	/**
	 * Test method for test the method {@link SimpleCrypt#encode(String)} and
	 * {@link SimpleCrypt#decode(String)}
	 */
	@Test
	public void testSimpleCrypt02()
	{
		String actual;
		String expected;
		String encrypted;
		String testString;
		int verschiebe;

		testString = "top secret";
		verschiebe = 4;

		expected = new StringBuffer(testString).toString().trim();
		encrypted = SimpleCrypt.encode(testString, verschiebe);
		actual = SimpleCrypt.decode(encrypted, verschiebe);
		assertEquals(actual, expected);
	}

	/**
	 * Test method for {@link SimpleCrypt} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		BeanTester beanTester = new BeanTester();
		beanTester.testBean(SimpleCrypt.class);
	}

}
