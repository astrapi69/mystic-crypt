/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto.key;

import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.crypto.provider.SecurityProvider;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link KeyExtensions}
 */
public class KeyExtensionsTest
{

	/**
	 * Test method for {@link KeyExtensions#readPrivateKey(File, SecurityProvider)}
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	@Test
	public void testReadDerPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException, IOException
	{
		final File publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		final File privatekeyDerFile = new File(publickeyDerDir, "private.der");

		final PrivateKey privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		assertNotNull(privateKey);
	}

	/**
	 * Test method for {@link KeyExtensions#readPemPrivateKey(File, SecurityProvider)}
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 *
	 */
	@Test
	public void testReadPemPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException, IOException
	{
		final File privatekeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File privatekeyPemFile = new File(privatekeyPemDir, "private.pem");

		Security.addProvider(new BouncyCastleProvider());
		final PrivateKey privateKey = PrivateKeyReader.readPemPrivateKey(privatekeyPemFile);

		assertNotNull(privateKey);
	}

}
