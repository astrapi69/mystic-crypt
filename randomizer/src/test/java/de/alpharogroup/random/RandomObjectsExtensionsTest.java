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
package de.alpharogroup.random;


import java.nio.CharBuffer;

import org.testng.AssertJUnit;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.BaseTestCase;

public class RandomObjectsExtensionsTest extends BaseTestCase
{

	@Override
	@BeforeMethod
	public void setUp() throws Exception
	{
	}

	@Override
	@AfterMethod
	public void tearDown() throws Exception
	{
	}

	/**
	 * Test method for {@link de.alpharogroup.random.RandomObjectsUtils#newRandomName(char[])} .
	 */
	@Test
	public void testCreatedRandomName()
	{
		final CharBuffer charBuffer = CharBuffer.allocate(Constants.LCCHARSWN.length());
		charBuffer.put(Constants.LCCHARSWN);
		final char[] donatedChars = Constants.LCCHARSWN.toCharArray();
		for (int i = 0; i < 100; i++)
		{
			final String randomName = RandomObjectsExtensions.newRandomName(donatedChars);
			this.result = randomName.contains(charBuffer);
			AssertJUnit.assertTrue("", this.result);
		}
	}

	/**
	 * Test method for {@link de.alpharogroup.random.RandomObjectsExtensions#newRandomId()}.
	 */
	@Test
	public void testCreateRandomId()
	{
		for (int i = 0; i < 1000; i++)
		{
			System.out.println(RandomObjectsExtensions.newRandomId());
		}

	}


	/**
	 * Test method for
	 * {@link de.alpharogroup.random.RandomObjectsExtensions#getInfomailFromWebsite(java.lang.String)} .
	 */
	@Test
	public void testGetInfomailFromWebsite()
	{
		final CharBuffer charBuffer = CharBuffer.allocate(Constants.LCCHARSWN.length());
		charBuffer.put(Constants.LCCHARSWN);
		final String url = RandomObjectsExtensions.getRandomWebsite();
		final String emailprefix = "info@";
		for (int i = 0; i < 100; i++)
		{
			final String randomInfomail = RandomObjectsExtensions.getInfomailFromWebsite(url);
			this.result = randomInfomail.startsWith(emailprefix);
			AssertJUnit.assertTrue("", this.result);

			this.result = randomInfomail.contains(charBuffer);
			AssertJUnit.assertTrue("", this.result);
		}
	}


	/**
	 * Test method for {@link de.alpharogroup.random.RandomObjectsExtensions#getRandomEmail()}.
	 */
	@Test
	public void testGetRandomEmail()
	{
		final CharBuffer charBuffer = CharBuffer.allocate(Constants.LCCHARSWN.length());
		charBuffer.put(Constants.LCCHARSWN);
		for (int i = 0; i < 100; i++)
		{
			final String randomEmail = RandomObjectsExtensions.getRandomEmail();
			this.result = randomEmail.contains(charBuffer);
			AssertJUnit.assertTrue("", this.result);
		}
	}

	/**
	 * Test method for
	 * {@link de.alpharogroup.random.RandomObjectsExtensions#getRandomFaxnumber(java.lang.String)} .
	 */
	@Test
	public void testGetRandomFaxnumber()
	{
		final CharBuffer charBuffer = CharBuffer.allocate(Constants.NUMBERS.length());
		charBuffer.put(Constants.NUMBERS);
		for (int i = 0; i < 100; i++)
		{
			final String randomPhonenumber = RandomObjectsExtensions.getRandomPhonenumber();
			final String randomFaxnumber = RandomObjectsExtensions.getRandomFaxnumber(randomPhonenumber);
			this.result = randomFaxnumber.contains(charBuffer);
			AssertJUnit.assertTrue("", this.result);
		}
	}


	/**
	 * Test method for {@link de.alpharogroup.random.RandomObjectsExtensions#getRandomMobilnumber()}.
	 */
	@Test
	public void testGetRandomMobilnumber()
	{
		final CharBuffer charBuffer = CharBuffer.allocate(Constants.NUMBERS.length());
		charBuffer.put(Constants.NUMBERS);
		for (int i = 0; i < 100; i++)
		{
			final String randomMobilnumber = RandomObjectsExtensions.getRandomMobilnumber();
			this.result = randomMobilnumber.contains(charBuffer);
			AssertJUnit.assertTrue("", this.result);
		}
	}

	@Test
	public void testGetRandomPassword()
	{
		final CharBuffer charBuffer = CharBuffer.allocate(26);
		final int length = 5;
		final String chars = Constants.LOWCASECHARS;
		charBuffer.put(chars);
		for (int i = 0; i < 100; i++)
		{
			final String randomPassword = RandomObjectsExtensions.getRandomPassword(length);
			this.result = randomPassword.contains(charBuffer);
			AssertJUnit.assertTrue("", this.result);
		}
	}

	/**
	 * Test method for {@link de.alpharogroup.random.RandomObjectsExtensions#getRandomPhonenumber()}.
	 */
	@Test
	public void testGetRandomPhonenumber()
	{
		final CharBuffer charBuffer = CharBuffer.allocate(Constants.NUMBERS.length());
		charBuffer.put(Constants.NUMBERS);
		for (int i = 0; i < 100; i++)
		{
			final String randomPhonenumber = RandomObjectsExtensions.getRandomPhonenumber();
			this.result = randomPhonenumber.contains(charBuffer);
			AssertJUnit.assertTrue("", this.result);
		}
	}

	/**
	 * Test method for {@link de.alpharogroup.random.RandomObjectsExtensions#getRandomWebsite()}.
	 */
	@Test
	public void testGetRandomWebsite()
	{
		final CharBuffer charBuffer = CharBuffer.allocate(Constants.LCCHARSWN.length());
		charBuffer.put(Constants.LCCHARSWN);
		for (int i = 0; i < 100; i++)
		{
			final String randomWebsite = RandomObjectsExtensions.getRandomWebsite();
			this.result = randomWebsite.contains(charBuffer);
			AssertJUnit.assertTrue("", this.result);
		}
	}

}
