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

import org.testng.AssertJUnit;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

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
