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

import org.apache.log4j.Logger;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

/**
 * Test class for the class {@link SimpleCrypt}.
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class SimpleCryptTest
{

	/** The Constant logger. */
	private static final Logger logger = Logger.getLogger(SimpleCryptTest.class.getName());

	/**
	 * Test method for test the method {@link SimpleCrypt#encode(String)} and
	 * {@link SimpleCrypt#decode(String)}.
	 */
	@Test
	public void testCryptoUtils()
	{
		final String testString = "top secret";
		final String expected = testString;
		final String encrypted = SimpleCrypt.encode(testString);
		final String decrypted = SimpleCrypt.decode(encrypted);
		AssertJUnit.assertTrue(decrypted.equals(expected));
		testCryptoUtils(testString, 4);
	}

	/**
	 * Test method for test the method {@link SimpleCrypt#encode(String)} and
	 * {@link SimpleCrypt#decode(String)}.
	 *
	 * @param testString
	 *            the test string
	 * @param verschiebe
	 *            the relocate
	 */
	protected void testCryptoUtils(final String testString, final int verschiebe)
	{
		logger.debug("original:--------\n" + testString + "\n--------");
		final String expected = new StringBuffer(testString).toString().trim();
		final String encrypted = SimpleCrypt.encode(testString, verschiebe);
		logger.debug("encrypted:--------\n" + encrypted + "\n--------");
		final String decrypted = SimpleCrypt.decode(encrypted, verschiebe);
		AssertJUnit.assertTrue(decrypted.equals(expected));
		logger.debug("decrypted:--------\n" + decrypted + "\n--------");
	}


}
