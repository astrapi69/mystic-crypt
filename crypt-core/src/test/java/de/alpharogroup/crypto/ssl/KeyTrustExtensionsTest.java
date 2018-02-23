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
package de.alpharogroup.crypto.ssl;

import static org.testng.Assert.assertNotNull;

import java.io.File;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.KeystoreType;
import de.alpharogroup.crypto.factories.KeyStoreFactory;
import de.alpharogroup.file.search.PathFinder;

/**
 * The class {@link KeyTrustExtensions}.
 */
public class KeyTrustExtensionsTest
{

	/**
	 * Test method for
	 * {@link KeyTrustExtensions#resolveTrustManagers(String, String, File, String)}.
	 */
	@Test
	public void testResolveTrustManagers() throws Exception
	{
		final File derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		final File keystoreFile = new File(derDir, "keystore.jks");

		final String keystoreType = KeystoreType.JKS.name();

		String password = "secret-pw";
		KeyStoreFactory.newKeyStore(keystoreType, password, keystoreFile, true);

		final String trustManagerAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
		TrustManager[] trustManagers = KeyTrustExtensions.resolveTrustManagers(keystoreType, password,
			keystoreFile, trustManagerAlgorithm);

		assertNotNull(trustManagers);
		// cleanup...
		keystoreFile.delete();
	}

	/**
	 * Test method for {@link KeyTrustExtensions#resolveKeyManagers(String, String, File, String)}.
	 */
	@Test
	public void testResolveKeyManagers() throws Exception
	{
		final File derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		final File keystoreFile = new File(derDir, "keystore.jks");

		final String keystoreType = KeystoreType.JKS.name();

		String password = "secret-pw";
		KeyStoreFactory.newKeyStore(keystoreType, password, keystoreFile, true);

		final String keyManagerAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
		KeyManager[] keyManagers = KeyTrustExtensions.resolveKeyManagers(keystoreType, password,
			keystoreFile, keyManagerAlgorithm);

		assertNotNull(keyManagers);
		// cleanup...
		keystoreFile.delete();
	}

}
