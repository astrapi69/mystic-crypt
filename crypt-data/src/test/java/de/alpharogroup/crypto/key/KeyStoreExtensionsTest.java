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

import static org.testng.Assert.assertTrue;
import static org.testng.AssertJUnit.assertFalse;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

import org.testng.AssertJUnit;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.KeystoreType;
import de.alpharogroup.crypto.factories.KeyStoreFactory;
import de.alpharogroup.crypto.key.reader.CertificateReader;
import de.alpharogroup.file.search.PathFinder;

/**
 * The class {@link KeyStoreExtensions}.
 */
public class KeyStoreExtensionsTest
{

	/** The certificate for tests. */
	X509Certificate certificate;
	String password = "foobar-secret-pw";
	String alias = "alias-for-delete";
	String newAlias = "new-alias";

	File publickeyDerDir;
	File privatekeyDerFile;

	/**
	 * Sets up method will be invoked before every unit test method in this class.
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@BeforeMethod
	protected void setUp() throws Exception
	{
		if (certificate == null)
		{
			final File pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
			final File certificatePemFile = new File(pemDir, "certificate.pem");
			certificate = CertificateReader.readPemCertificate(certificatePemFile);
			AssertJUnit.assertNotNull(certificate);

		}

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privatekeyDerFile = new File(publickeyDerDir, "keystore.jks");
		KeyStore keyStore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), password,
			privatekeyDerFile, true);
		AssertJUnit.assertNotNull(keyStore);
		assertFalse(keyStore.containsAlias(alias));
		keyStore.setCertificateEntry(alias, certificate);

		assertTrue(keyStore.containsAlias(alias));
		keyStore.store(new FileOutputStream(privatekeyDerFile), password.toCharArray());
	}

	/**
	 * Tear down method will be invoked after every unit test method
	 *
	 * @throws Exception
	 *             is thrown if an exception occurs
	 */
	@AfterMethod
	protected void tearDown() throws Exception
	{
		privatekeyDerFile.delete();
	}

	/**
	 * Test method for {@link KeyStoreExtensions#deleteAlias(File, String, String)}.
	 */
	@Test
	public void testDeleteAlias() throws Exception
	{
		KeyStoreExtensions.deleteAlias(privatekeyDerFile, alias, password);

		KeyStore keyStore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), password,
			privatekeyDerFile, true);
		boolean containsAlias = keyStore.containsAlias(alias);

		assertFalse(containsAlias);
	}

}
