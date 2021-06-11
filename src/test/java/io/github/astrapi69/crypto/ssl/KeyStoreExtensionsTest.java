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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertTrue;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import io.github.astrapi69.crypto.sign.TestObjectFactory;
import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.collections.array.ArrayFactory;
import io.github.astrapi69.crypto.algorithm.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypto.algorithm.KeystoreType;
import io.github.astrapi69.crypto.factories.KeyPairFactory;
import io.github.astrapi69.crypto.factories.KeyStoreFactory;
import io.github.astrapi69.crypto.key.KeySize;
import io.github.astrapi69.crypto.key.reader.CertificateReader;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link KeyStoreExtensions}
 */
public class KeyStoreExtensionsTest
{

	String alias = "alias-for-delete";
	/** The certificate for tests. */
	X509Certificate certificate;
	File derDir;
	File keystoreFile;

	String newAlias = "new-alias";
	String password = "foobar-secret-pw";

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
			assertNotNull(certificate);

		}

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		keystoreFile = new File(derDir, "keystore.jks");
		KeyStore keyStore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), password,
			keystoreFile, true);
		assertNotNull(keyStore);
		assertFalse(keyStore.containsAlias(alias));
		keyStore.setCertificateEntry(alias, certificate);

		assertTrue(keyStore.containsAlias(alias));
		keyStore.store(new FileOutputStream(keystoreFile), password.toCharArray());
	}

	/**
	 * Tear down method will be invoked after every unit test method
	 */
	@AfterMethod
	protected void tearDown()
	{
		keystoreFile.delete();
	}

	/**
	 * Test method for
	 * {@link KeyStoreExtensions#addAndStoreCertificate(KeyStore, File, String, String, Certificate)}
	 */
	@Test
	public void testAddAndStoreCertificate() throws Exception
	{
		Certificate actual;
		Certificate expected;
		PrivateKey privateKey;
		KeyPair keyPair;
		Certificate certificate;
		String alias;
		KeyStore keyStore;

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_2048);
		privateKey = keyPair.getPrivate();

		keyStore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), password, keystoreFile,
			false);

		certificate = TestObjectFactory.newCertificateForTests(privateKey);

		alias = newAlias;

		KeyStoreExtensions.addAndStoreCertificate(keyStore, keystoreFile, password, alias,
			certificate);
		// load again keystore from file
		keyStore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), password, keystoreFile,
			false);
		actual = keyStore.getCertificate(alias);
		assertNotNull(actual);
		expected = certificate;
		assertEquals(actual, expected);
	}

	/**
	 * Test method for
	 * {@link KeyStoreExtensions#addAndStorePrivateKey(KeyStore, File, String, PrivateKey, char[], Certificate[])}
	 */
	@Test
	public void testAddAndStorePrivateKey() throws Exception
	{
		PrivateKey actual;
		PrivateKey expected;
		KeyPair keyPair;
		Certificate certificate;
		Certificate[] certificateChain;
		String alias;
		KeyStore keyStore;

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_2048);
		expected = keyPair.getPrivate();

		keyStore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), password, keystoreFile,
			false);

		certificate = TestObjectFactory.newCertificateForTests(expected);
		certificateChain = ArrayFactory.newArray(certificate);

		alias = "test-pk";

		KeyStoreExtensions.addAndStorePrivateKey(keyStore, keystoreFile, alias, expected,
			password.toCharArray(), certificateChain);
		// load again keystore from file
		keyStore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), password, keystoreFile,
			false);

		actual = (PrivateKey)keyStore.getKey(alias, password.toCharArray());
		assertNotNull(actual);
		assertEquals(actual, expected);

		actual = KeyStoreExtensions.getPrivateKey(keyStore, alias, password.toCharArray());
		assertNotNull(actual);
		assertEquals(actual, expected);

		Certificate certificate1 = keyStore.getCertificate(alias);
		assertEquals(certificate, certificate1);
	}


	/**
	 * Test method for {@link KeyStoreExtensions#addCertificate(KeyStore, String, Certificate)}
	 */
	@Test
	public void testAddCertificate() throws Exception
	{
		Certificate actual;
		Certificate expected;
		PrivateKey privateKey;
		KeyPair keyPair;
		Certificate certificate;
		String alias;
		KeyStore keyStore;

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_2048);
		privateKey = keyPair.getPrivate();

		keyStore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), password, keystoreFile,
			false);

		certificate = TestObjectFactory.newCertificateForTests(privateKey);

		alias = newAlias;

		KeyStoreExtensions.addCertificate(keyStore, alias, certificate);

		actual = keyStore.getCertificate(alias);
		assertNotNull(actual);
		expected = certificate;
		assertEquals(actual, expected);
	}

	/**
	 * Test method for
	 * {@link KeyStoreExtensions#addPrivateKey(KeyStore, String, PrivateKey, char[], Certificate[])}
	 */
	@Test
	public void testAddPrivateKey() throws Exception
	{
		PrivateKey actual;
		PrivateKey expected;
		KeyPair keyPair;
		Certificate certificate;
		Certificate[] certificateChain;
		String alias;
		KeyStore keyStore;

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_2048);
		expected = keyPair.getPrivate();

		keyStore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), password, keystoreFile,
			false);

		certificate = TestObjectFactory.newCertificateForTests(expected);
		certificateChain = ArrayFactory.newArray(certificate);

		alias = "test-pk";

		KeyStoreExtensions.addPrivateKey(keyStore, alias, expected, password.toCharArray(),
			certificateChain);

		actual = (PrivateKey)keyStore.getKey(alias, password.toCharArray());
		assertNotNull(actual);
		assertEquals(actual, expected);

		actual = KeyStoreExtensions.getPrivateKey(keyStore, alias, password.toCharArray());
		assertNotNull(actual);
		assertEquals(actual, expected);

		Certificate certificate1 = keyStore.getCertificate(alias);
		assertEquals(certificate, certificate1);
	}

	/**
	 * Test method for
	 * {@link de.alpharogroup.crypto.key.KeyStoreExtensions#deleteAlias(File, String, String)}
	 */
	@Test
	public void testDeleteAlias() throws Exception
	{
		KeyStore keyStore;
		boolean containsAlias;

		KeyStoreExtensions.deleteAlias(keystoreFile, alias, password);

		keyStore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), password, keystoreFile,
			false);
		containsAlias = keyStore.containsAlias(alias);

		assertFalse(containsAlias);
	}

	/**
	 * Test method for {@link KeyStoreExtensions#getCertificate(KeyStore, String)}
	 */
	@Test
	public void testGetCertificate() throws Exception
	{
		Certificate actual;
		Certificate expected;
		PrivateKey privateKey;
		KeyPair keyPair;
		Certificate certificate;
		String alias;
		KeyStore keyStore;

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_2048);
		privateKey = keyPair.getPrivate();

		keyStore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), password, keystoreFile,
			false);

		certificate = TestObjectFactory.newCertificateForTests(privateKey);

		alias = newAlias;

		KeyStoreExtensions.addCertificate(keyStore, alias, certificate);

		actual = KeyStoreExtensions.getCertificate(keyStore, alias);
		assertNotNull(actual);
		expected = certificate;
		assertEquals(actual, expected);
	}

	/**
	 * Test method for {@link KeyStoreExtensions#getPrivateKey(KeyStore, String, char[])}
	 */
	@Test
	public void testGetPrivateKey() throws Exception
	{
		PrivateKey actual;
		PrivateKey expected;
		KeyPair keyPair;
		Certificate certificate;
		Certificate[] certificateChain;
		String alias;
		KeyStore keyStore;

		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, KeySize.KEYSIZE_2048);
		expected = keyPair.getPrivate();

		keyStore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), password, keystoreFile,
			false);

		certificate = TestObjectFactory.newCertificateForTests(expected);
		certificateChain = ArrayFactory.newArray(certificate);

		alias = "test-pk";

		KeyStoreExtensions.addPrivateKey(keyStore, alias, expected, password.toCharArray(),
			certificateChain);

		actual = (PrivateKey)keyStore.getKey(alias, password.toCharArray());
		assertNotNull(actual);
		assertEquals(actual, expected);

		actual = KeyStoreExtensions.getPrivateKey(keyStore, alias, password.toCharArray());
		assertNotNull(actual);
		assertEquals(actual, expected);
	}


	/**
	 * Test method for {@link KeyStoreFactory#newKeyStore(String, String, File, boolean)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             if the algorithm used to check the integrity of the keystore cannot be found
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list
	 * @throws CertificateException
	 *             if any of the certificates in the keystore could not be loaded
	 * @throws FileNotFoundException
	 *             if the file not found
	 * @throws KeyStoreException
	 *             if the keystore has not been initialized (loaded).
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test(enabled = false)
	public void testNewKeyStore() throws NoSuchAlgorithmException, NoSuchProviderException,
		CertificateException, FileNotFoundException, KeyStoreException, IOException,
		InvalidKeySpecException, InvalidKeyException, SignatureException, UnrecoverableKeyException
	{

		PrivateKey actual;
		File publickeyDerDir;
		File keystoreJksFile;
		KeyStore keystore;
		PrivateKey expected;
		Certificate certificate;
		Certificate[] certificateChain;
		String alias;
		String password = "keystore-pw";

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		keystoreJksFile = new File(publickeyDerDir, "keystore-new.jks");

		keystore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), password, keystoreJksFile,
			true);
		assertNotNull(keystore);

		KeyPair keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA,
			KeySize.KEYSIZE_2048);
		expected = keyPair.getPrivate();
		certificate = TestObjectFactory.newCertificateForTests(expected);
		certificateChain = ArrayFactory.newArray(certificate);

		alias = "app-priv-key";

		KeyStoreExtensions.addPrivateKey(keystore, alias, expected, password.toCharArray(),
			certificateChain);

		actual = (PrivateKey)keystore.getKey(alias, password.toCharArray());
		assertNotNull(actual);
		assertEquals(actual, expected);

		Certificate certificate1 = keystore.getCertificate(alias);
		assertEquals(certificate, certificate1);

		keystore.store(new FileOutputStream(keystoreJksFile), password.toCharArray());

		// FileUtils.deleteQuietly(keystoreJksFile);
	}

	/**
	 * Test method for {@link io.github.astrapi69.crypto.key.KeyStoreExtensions} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(io.github.astrapi69.crypto.key.KeyStoreExtensions.class);
	}

}
