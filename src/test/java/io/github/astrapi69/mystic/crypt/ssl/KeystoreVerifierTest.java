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
package io.github.astrapi69.mystic.crypt.ssl;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.collection.array.ArrayFactory;
import io.github.astrapi69.crypt.data.factory.CertFactory;
import io.github.astrapi69.crypt.data.factory.KeyStoreFactory;
import io.github.astrapi69.crypt.data.key.KeyStoreExtensions;
import io.github.astrapi69.crypt.data.model.DistinguishedNameInfo;
import io.github.astrapi69.crypt.data.model.ExtensionInfo;
import io.github.astrapi69.crypt.data.model.KeyPairInfo;
import io.github.astrapi69.crypt.data.model.Validity;
import io.github.astrapi69.crypt.data.model.X509CertificateV1Info;
import io.github.astrapi69.crypt.data.model.X509CertificateV3Info;
import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.delete.DeleteFileExtensions;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.random.number.RandomBigIntegerFactory;

/**
 * This class contains JUnit 5 tests for the KeystoreChecker class. It aims to cover all methods
 * under various scenarios to ensure high code coverage and correct functionality.
 */
class KeystoreVerifierTest
{

	private static final String KEYSTORE_FILENAME = "ssl-keystore.jks";
	private static final String PASSWORD = "password";
	private File keystoreFile;

	/**
	 * Setup method to initialize a keystore for the tests.
	 */
	@BeforeEach
	public void setUp() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());

		DistinguishedNameInfo distinguishedNameInfo;
		KeyPair keyPair;

		KeyPairInfo keyPairInfo;
		BigInteger serial;
		X509Certificate certificate;
		ExtensionInfo[] extensionInfos;

		distinguishedNameInfo = DistinguishedNameInfo.builder().commonName("Test Server")
			.countryCode("GB").location("London").organisation("My Company")
			.organisationUnit("IT Department").state("Greater London").build();

		keyPairInfo = KeyPairInfo.builder().algorithm("RSA").keySize(2048).build();

		keyPair = KeyPairInfo.toKeyPair(keyPairInfo);
		extensionInfos = ArrayFactory.newArray(ExtensionInfo.builder()
			.extensionId("1.3.6.1.5.5.7.3.2").critical(false).value("foo bar").build());

		serial = RandomBigIntegerFactory.randomBigInteger();
		X509CertificateV1Info x509CertificateV1Info = X509CertificateV1Info.builder()
			.issuer(distinguishedNameInfo).serial(serial)
			.validity(Validity.builder().notBefore(ZonedDateTime.parse("2024-01-01T00:00:00Z"))
				.notAfter(ZonedDateTime.parse("2034-01-01T00:00:00Z")).build())
			.subject(distinguishedNameInfo).signatureAlgorithm("SHA256withRSA").build();

		X509CertificateV3Info x509CertificateV3Info = X509CertificateV3Info.builder()
			.certificateV1Info(x509CertificateV1Info).extensions(extensionInfos).build();

		certificate = CertFactory.newX509CertificateV3(keyPair, x509CertificateV3Info);

		keystoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(), KEYSTORE_FILENAME);

		KeyStore keyStore = KeyStoreFactory.newKeyStore(keystoreFile, "JKS", PASSWORD);
		KeyStoreExtensions.setKeyEntry(keyStore, "serverKey", keyPair.getPrivate(),
			PASSWORD.toCharArray(), new X509Certificate[] { certificate });
		KeyStoreExtensions.store(keyStore, keystoreFile, PASSWORD);
	}

	/**
	 * Tear down method will be invoked after every unit test method in this class
	 *
	 * @throws Exception
	 *             is thrown if an exception occurs
	 */
	@AfterEach
	public void tearDown() throws IOException
	{

		DeleteFileExtensions.delete(keystoreFile);
	}

	/**
	 * Test to verify that a valid keystore file is correctly identified.
	 */
	@Test
	public void testValidKeystore() throws IOException
	{
		String validKeystorePath = keystoreFile.getAbsolutePath();
		assertTrue(KeystoreVerifier.isKeystoreFile(validKeystorePath, PASSWORD));
	}

	/**
	 * Test to verify that an invalid keystore file is correctly identified as invalid.
	 */
	@Test
	public void testInvalidKeystore()
	{
		String invalidKeystorePath = "path/to/invalid/keystore.jks";
		assertFalse(KeystoreVerifier.isKeystoreFile(invalidKeystorePath, PASSWORD));
	}

	/**
	 * Test to verify that a valid keystore file of a specific type is recognized.
	 */
	@Test
	public void testValidKeystoreWithType() throws IOException
	{
		String validKeystorePath = keystoreFile.getAbsolutePath();
		String type = "JKS";
		assertTrue(KeystoreVerifier.isKeystoreFile(validKeystorePath, PASSWORD, type));
	}

	/**
	 * Test to verify that a valid keystore file of specific types is recognized.
	 */
	@Test
	public void testValidKeystoreWithTypes() throws IOException
	{
		String validKeystorePath = keystoreFile.getAbsolutePath();
		String[] types = { "JKS", "PKCS12" };
		assertTrue(KeystoreVerifier.isKeystoreFile(validKeystorePath, PASSWORD, types));
	}

	/**
	 * Test to verify that an invalid keystore file or incorrect password is identified.
	 */
	@Test
	public void testInvalidKeystoreWithType()
	{
		String invalidKeystorePath = "path/to/invalid/keystore.jks";
		String[] types = { "JKS", "PKCS12" };
		assertFalse(KeystoreVerifier.isKeystoreFile(invalidKeystorePath, "wrongpassword", types));
	}

	/**
	 * Test to verify that a File object representing a valid keystore is recognized.
	 */
	@Test
	public void testKeystoreFileObject() throws IOException
	{
		assertTrue(KeystoreVerifier.isKeystoreFile(keystoreFile, PASSWORD));
	}

	/**
	 * Test to verify that a File object representing a valid keystore is recognized.
	 */
	@Test
	public void testKeystoreFileObjectWithTypes() throws IOException
	{
		String[] types = { "JKS", "PKCS12" };
		assertTrue(KeystoreVerifier.isKeystoreFile(keystoreFile, PASSWORD, types));
	}
}
