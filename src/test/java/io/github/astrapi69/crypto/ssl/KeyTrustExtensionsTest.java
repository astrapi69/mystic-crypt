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
package io.github.astrapi69.crypto.ssl;

import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import io.github.astrapi69.crypto.algorithm.KeystoreType;
import io.github.astrapi69.crypto.factories.KeyStoreFactory;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The unit test class for the class {@link KeyTrustExtensions}
 */
public class KeyTrustExtensionsTest
{

	/**
	 * Test method for {@link KeyTrustExtensions#resolveKeyManagers(String, String, File, String)}
	 */
	@Test
	public void testResolveKeyManagers() throws Exception
	{
		File derDir;
		File keystoreFile;
		String keystoreType;
		String password;
		String keyManagerAlgorithm;
		KeyManager[] keyManagers;

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		keystoreFile = new File(derDir, "keystore.jks");

		keystoreType = KeystoreType.JKS.name();

		password = "secret-pw";

		KeyStoreFactory.newKeyStore(keystoreType, password, keystoreFile, true);

		keyManagerAlgorithm = KeyManagerFactory.getDefaultAlgorithm();
		keyManagers = KeyTrustExtensions.resolveKeyManagers(keystoreType, password, keystoreFile,
			keyManagerAlgorithm);

		assertNotNull(keyManagers);
		// cleanup...
		keystoreFile.delete();
	}

	/**
	 * Test method for {@link KeyTrustExtensions#resolveTrustManagers(String, String, File, String)}
	 */
	@Test
	public void testResolveTrustManagers() throws Exception
	{
		File derDir;
		File keystoreFile;
		String keystoreType;
		String password;
		String trustManagerAlgorithm;
		TrustManager[] trustManagers;

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "/der");
		keystoreFile = new File(derDir, "keystore.jks");

		keystoreType = KeystoreType.JKS.name();

		password = "secret-pw";
		KeyStoreFactory.newKeyStore(keystoreType, password, keystoreFile, true);

		trustManagerAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
		trustManagers = KeyTrustExtensions.resolveTrustManagers(keystoreType, password,
			keystoreFile, trustManagerAlgorithm);

		assertNotNull(trustManagers);
		// cleanup...
		keystoreFile.delete();
	}

	/**
	 * Test method for {@link KeyTrustExtensions} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		BeanTester beanTester = new BeanTester();
		beanTester.testBean(KeyTrustExtensions.class);
	}

}
