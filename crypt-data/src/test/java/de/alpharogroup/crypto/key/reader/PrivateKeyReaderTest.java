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
package de.alpharogroup.crypto.key.reader;

import java.io.File;
import java.security.PrivateKey;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.PrivateKeyExtensions;
import de.alpharogroup.crypto.provider.SecurityProvider;
import de.alpharogroup.file.search.PathFinder;

/**
 * Test class for {@link PrivateKeyReader}.
 */
public class PrivateKeyReaderTest
{

	/**
	 * Test method for {@link PrivateKeyReader#readPrivateKey(File)}.
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testReadPemFileAsBase64() throws Exception
	{
		final File privatekeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File privatekeyPemFile = new File(privatekeyPemDir, "private.pem");

		Security.addProvider(new BouncyCastleProvider());
		final String privateKeyAsBase64String = PrivateKeyReader
			.readPemFileAsBase64(privatekeyPemFile);

		final PrivateKey privateKey = PrivateKeyReader.readPemPrivateKey(privatekeyPemFile);

		final String base64 = PrivateKeyExtensions.toBase64(privateKey);
		AssertJUnit.assertNotNull(privateKeyAsBase64String);
		AssertJUnit.assertNotNull(base64);
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPemPrivateKey(File, SecurityProvider)}.
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test(enabled = true)
	public void testReadPemPrivateKey() throws Exception
	{
		final File privatekeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File privatekeyPemFile = new File(privatekeyPemDir, "private.pem");

		Security.addProvider(new BouncyCastleProvider());
		final PrivateKey privateKey = PrivateKeyReader.readPemPrivateKey(privatekeyPemFile);		
		AssertJUnit.assertNotNull(privateKey);
	}


	/**
	 * Test method for {@link PrivateKeyReader#readPrivateKey(File)}.
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testReadPrivateKey() throws Exception
	{
		final File publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		final File privatekeyDerFile = new File(publickeyDerDir, "private.der");

		final PrivateKey privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		AssertJUnit.assertNotNull(privateKey);
	}

}
