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
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.crypto.key.reader.PublicKeyReader;
import de.alpharogroup.crypto.provider.SecurityProvider;
import de.alpharogroup.file.read.ReadFileExtensions;
import de.alpharogroup.file.search.PathFinder;

/**
 * Test class for the class {@link PrivateKeyExtensions}.
 */
public class PrivateKeyExtensionsTest
{

	/**
	 * Test method for {@link PrivateKeyExtensions#generatePublicKey(PrivateKey)}
	 *
	 * @throws Exception
	 *             is thrown if an security error occurs
	 */
	@Test
	public void testGeneratePublicKey() throws Exception
	{

		final File keyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File publickeyPemFile = new File(keyPemDir, "public.pem");
		final File privatekeyPemFile = new File(keyPemDir, "private.pem");

		Security.addProvider(new BouncyCastleProvider());
		final PrivateKey privateKey = PrivateKeyReader.readPemPrivateKey(privatekeyPemFile,
			SecurityProvider.BC);

		final PublicKey expected = PublicKeyReader.readPemPublicKey(publickeyPemFile,
			SecurityProvider.BC);

		final PublicKey actual = PrivateKeyExtensions.generatePublicKey(privateKey);
		AssertJUnit.assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link PrivateKeyExtensions#toBase64(PublicKey)}
	 *
	 * @throws Exception
	 *             is thrown if an security error occurs
	 *
	 */
	@Test(enabled = false)
	public void testToPemFormat() throws Exception
	{
		final File keyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File privatekeyPemFile = new File(keyPemDir, "private.pem");

		Security.addProvider(new BouncyCastleProvider());
		final PrivateKey privateKey = PrivateKeyReader.readPemPrivateKey(privatekeyPemFile,
			SecurityProvider.BC);

		final String pemFormat = PrivateKeyExtensions.toPemFormat(privateKey);
		final String expected = ReadFileExtensions.readFromFile(privatekeyPemFile);
		AssertJUnit.assertEquals(pemFormat, expected);
	}

}
