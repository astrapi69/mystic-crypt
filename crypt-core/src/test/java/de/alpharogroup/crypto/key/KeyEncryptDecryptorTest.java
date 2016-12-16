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
package de.alpharogroup.crypto.key;


import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.testng.AssertJUnit;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.file.search.PathFinder;

public class KeyEncryptDecryptorTest
{

	@BeforeMethod
	public void setUp() throws Exception
	{
	}

	@AfterMethod
	public void tearDown() throws Exception
	{
	}

	@Test(enabled=true)
	public void testEncryptDecrypt() throws Exception
	{
		final String test = "I'm an hellenic boy and will be encrypted with the KeyEncryptor;-)";
		System.out.println("String before encryption:");
		System.out.println(test);

		final File publickeyDerFile = new File(PathFinder.getSrcTestResourcesDir(), "public.der");
		final File privatekeyDerFile = new File(PathFinder.getSrcTestResourcesDir(), "private.der");

		final File publickeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File publickeyPemFile = new File(publickeyPemDir, "public.pem");
		final File privatekeyPemFile = new File(publickeyPemDir, "private.pem");

		final PrivateKey privateKey = KeyExtensions.readPemPrivateKey(privatekeyPemFile);

		final PublicKey publicKey = KeyExtensions.readPemPublicKey(publickeyPemFile);

		final KeyEncryptor encryptor = new KeyEncryptor(publicKey);

		final String encrypted = encryptor.encrypt(test);
		System.out.println("String after encryption:");
		System.out.println(encrypted);
		final KeyDecryptor decryptor = new KeyDecryptor(privateKey);
		final String decryted = decryptor.decrypt(encrypted);
		System.out.println("String after decryption:");
		System.out.println(decryted);
		AssertJUnit.assertTrue("String before encryption is not equal after decryption.",
			test.equals(decryted));
	}

}
