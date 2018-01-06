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
package de.alpharogroup.crypto.processors.bruteforce;

import java.io.IOException;
import java.sql.Date;
import java.util.Set;

import org.apache.log4j.Logger;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import de.alpharogroup.lang.PackageExtensions;

/**
 * Test class for {@link BruteForceProcessor}.
 */
public class BruteForceProcessorTest
{

	/** The Constant logger. */
	private static final Logger logger = Logger.getLogger(BruteForceProcessorTest.class.getName());

	/**
	 * Test method for test the class {@link BruteForceProcessor}.
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test(enabled = false)
	public void test() throws IOException
	{

		final Set<String> list = PackageExtensions.scanClassNames("de.alpharogroup", true, true);
		for (final String string : list)
		{
			if (string.endsWith("Test"))
			{
				logger.debug("<class name=\"" + string + "\"/>");
			}
		}

		String password;
		char[] possibleCharacters;
		password = "hash";
		possibleCharacters = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
				'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

		final BruteForceProcessor processor = new BruteForceProcessor(possibleCharacters, 1);
		String attempt = processor.getCurrentAttempt();
		boolean found = false;
		final long start = System.currentTimeMillis();
		while (true)
		{
			if (attempt.equals(password))
			{
				logger.debug("Password Found: " + attempt);
				found = true;
				break;
			}
			attempt = processor.getCurrentAttempt();
			logger.debug("Tried: " + attempt);
			processor.increment();
		}
		final long end = System.currentTimeMillis();

		logger.debug("Started of the brute force attack for the password: " + new Date(start));
		logger.debug("Ended of the brute force attack for the password: " + new Date(end));
		AssertJUnit.assertTrue(found);
	}

}
