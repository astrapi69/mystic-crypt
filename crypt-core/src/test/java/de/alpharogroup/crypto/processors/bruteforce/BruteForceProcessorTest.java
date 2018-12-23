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

import static org.testng.AssertJUnit.assertTrue;

import java.io.IOException;
import java.util.Set;

import org.testng.annotations.Test;

import de.alpharogroup.lang.PackageExtensions;

/**
 * The unit test class for the class {@link BruteForceProcessor}
 */
public class BruteForceProcessorTest
{

	/**
	 * Test method for test the class {@link BruteForceProcessor}.
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test(enabled = true)
	public void test() throws IOException
	{

		final Set<String> list = PackageExtensions.scanClassNames("de.alpharogroup", true, true);
		for (final String string : list)
		{
			if (string.endsWith("Test"))
			{
				System.out.println("<class name=\"" + string + "\"/>");
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
				System.out.println("Password Found: " + attempt);
				found = true;
				break;
			}
			attempt = processor.getCurrentAttempt();
			System.out.println("Tried: " + attempt);
			processor.increment();
		}
		final long end = System.currentTimeMillis();

		long elapsedMilliSeconds = end - start;
		assertTrue(found);

		System.out.println("Started brute force attack for the password '" + password + "'.");
		System.out.println("Needed milliseconds for crack the password with brute force attack: "
			+ elapsedMilliSeconds);
		System.out.println("Password found: " + found);
	}

}
