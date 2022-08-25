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
package io.github.astrapi69.mystic.crypt.processor.bruteforce;

import static org.testng.AssertJUnit.assertTrue;

import java.io.IOException;
import java.util.Set;
import java.util.logging.Logger;

import org.testng.annotations.Test;

import io.github.astrapi69.io.annotations.ScanPackageExtensions;

/**
 * The unit test class for the class {@link BruteForceProcessor}
 */
public class BruteForceProcessorTest
{

	private static final Logger log = Logger.getLogger(BruteForceProcessorTest.class.getName());

	/**
	 * Test method for test the class {@link BruteForceProcessor}.
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test(enabled = false)
	public void test() throws IOException
	{

		String password;
		char[] possibleCharacters;
		BruteForceProcessor processor;
		String attempt;
		boolean found;
		long start;
		long end;
		long elapsedMilliSeconds;
		Set<String> list;

		list = ScanPackageExtensions.scanClassNames("de.alpharogroup", true, true);
		for (final String string : list)
		{
			if (string.endsWith("Test"))
			{
				log.info("<class name=\"" + string + "\"/>");
			}
		}

		password = "ha";
		possibleCharacters = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
				'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

		processor = new BruteForceProcessor(possibleCharacters, 1);
		attempt = processor.getCurrentAttempt();

		start = System.currentTimeMillis();
		while (true)
		{
			if (attempt.equals(password))
			{
				log.info("Password Found: " + attempt);
				found = true;
				break;
			}
			attempt = processor.getCurrentAttempt();
			log.info("Tried: " + attempt);
			processor.increment();
		}
		end = System.currentTimeMillis();

		elapsedMilliSeconds = end - start;
		assertTrue(found);

		log.info("Started brute force attack for the password '" + password + "'.");
		log.info("Needed milliseconds for crack the password with brute force attack: "
			+ elapsedMilliSeconds);
		log.info("Password found: " + found);
	}

}
