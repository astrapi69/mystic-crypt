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
package de.alpharogroup.crypto;

import org.testng.AssertJUnit;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.simple.SimpleCrypt;

/**
 * Test class for the class {@link SimpleCryptTest}.
 *
 * @version 1.0
 * @author Asterios Raptis
 */
public class SimpleCryptTest
{


	@BeforeMethod
	public void setUp() throws Exception
	{
	}


	@AfterMethod
	public void tearDown() throws Exception
	{
	}

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

	protected void testCryptoUtils(final String testString, final int verschiebe)
	{
		System.out.println("original:--------\n" + testString + "\n--------");
		final String expected = new StringBuffer(testString).toString().trim();
		final String encrypted = SimpleCrypt.encode(testString, verschiebe);
		System.out.println("encrypted:--------\n" + encrypted + "\n--------");
		final String decrypted = SimpleCrypt.decode(encrypted, verschiebe);
		AssertJUnit.assertTrue(decrypted.equals(expected));
		System.out.println("decrypted:--------\n" + decrypted + "\n--------");
	}


}
