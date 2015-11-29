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
package de.alpharogroup.crypto;


import java.io.IOException;
import java.sql.Date;
import java.util.Set;

import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import de.alpharogroup.lang.PackageExtensions;

public class BruteForceProcessorTest
{

	@Test
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

		System.out
			.println("Started of the brute force attack for the password: " + new Date(start));
		System.out.println("Ended of the brute force attack for the password: " + new Date(end));
		AssertJUnit.assertTrue(found);
	}

}
