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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.astrapi69.crypt.api.type.KeystoreType;
import io.github.astrapi69.crypt.data.factory.CertFactory;
import io.github.astrapi69.crypt.data.factory.KeyStoreFactory;
import io.github.astrapi69.crypt.data.model.DistinguishedNameInfo;
import io.github.astrapi69.crypt.data.model.KeyPairInfo;
import io.github.astrapi69.crypt.data.model.Validity;
import io.github.astrapi69.crypt.data.model.X509CertificateV1Info;
import io.github.astrapi69.random.number.RandomBigIntegerFactory;

/**
 * The unit test class for the class {@link KeyStoreExtensions}
 */
// KeyStoreExtensions is deprecated in favour of
// io.github.astrapi69.crypt.data.key.KeyStoreExtensions and will be removed with the next minor
// version. This test class exists precisely to keep the deprecated API working until that removal,
// so referencing it is intentional and the deprecation warning is not a defect here. Migrating the
// test to the replacement class would leave the deprecated class untested while it is still
// shipped.
@SuppressWarnings("deprecation")
class KeyStoreExtensionsTest
{

	private static final String PASSWORD = "secret-pw";
	private static final String ALIAS = "server-key";

	private static KeyPair keyPair;
	private static X509Certificate certificate;

	@TempDir
	File temporaryDirectory;

	private File keystoreFile;
	private KeyStore keyStore;

	/**
	 * Creates the key pair and the self signed certificate that all tests share
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@BeforeAll
	static void newKeyPairAndCertificate() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());

		DistinguishedNameInfo distinguishedNameInfo = DistinguishedNameInfo.builder()
			.commonName("Test Server").countryCode("GB").location("London")
			.organisation("My Company").organisationUnit("IT Department").state("Greater London")
			.build();
		keyPair = KeyPairInfo
			.toKeyPair(KeyPairInfo.builder().algorithm("RSA").keySize(2048).build());
		BigInteger serial = RandomBigIntegerFactory.randomBigInteger();
		X509CertificateV1Info x509CertificateV1Info = X509CertificateV1Info.builder()
			.issuer(distinguishedNameInfo).serial(serial)
			.validity(Validity.builder().notBefore(ZonedDateTime.parse("2024-01-01T00:00:00Z"))
				.notAfter(ZonedDateTime.parse("2034-01-01T00:00:00Z")).build())
			.subject(distinguishedNameInfo).signatureAlgorithm("SHA256withRSA").build();
		certificate = CertFactory.newX509CertificateV1(keyPair, x509CertificateV1Info);
	}

	/**
	 * Creates an empty keystore file for every test
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@BeforeEach
	void newEmptyKeyStore() throws Exception
	{
		keystoreFile = new File(temporaryDirectory, "test-keystore.jks");
		keyStore = KeyStoreFactory.newKeyStore(keystoreFile, KeystoreType.JKS.name(), PASSWORD);
	}

	private KeyStore reloadKeyStore() throws Exception
	{
		return KeyStoreFactory.loadKeyStore(keystoreFile, KeystoreType.JKS.name(), PASSWORD);
	}

	/**
	 * Test method for
	 * {@link KeyStoreExtensions#addAndStorePrivateKey(KeyStore, File, String, PrivateKey, char[], Certificate[])}
	 * and {@link KeyStoreExtensions#getPrivateKey(KeyStore, String, char[])}
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	void addAndStorePrivateKey_writesAPrivateKeyThatCanBeReadBackFromTheFile() throws Exception
	{
		KeyStoreExtensions.addAndStorePrivateKey(keyStore, keystoreFile, ALIAS,
			keyPair.getPrivate(), PASSWORD.toCharArray(), new Certificate[] { certificate });

		KeyStore reloaded = reloadKeyStore();
		assertTrue(reloaded.containsAlias(ALIAS));
		assertEquals(keyPair.getPrivate(),
			KeyStoreExtensions.getPrivateKey(reloaded, ALIAS, PASSWORD.toCharArray()));
		assertEquals(certificate, KeyStoreExtensions.getCertificate(reloaded, ALIAS));
	}

	/**
	 * Test method for
	 * {@link KeyStoreExtensions#addAndStoreCertificate(KeyStore, File, String, String, Certificate)}
	 * and {@link KeyStoreExtensions#getCertificate(KeyStore, String)}
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	void addAndStoreCertificate_writesACertificateThatCanBeReadBackFromTheFile() throws Exception
	{
		KeyStoreExtensions.addAndStoreCertificate(keyStore, keystoreFile, PASSWORD, "trusted-cert",
			certificate);

		KeyStore reloaded = reloadKeyStore();
		assertEquals(certificate, KeyStoreExtensions.getCertificate(reloaded, "trusted-cert"));
		assertTrue(reloaded.isCertificateEntry("trusted-cert"));
	}

	/**
	 * Test method for {@link KeyStoreExtensions#addCertificate(KeyStore, String, Certificate)},
	 * adding an entry only changes the in memory keystore until it is stored
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	void addCertificate_changesOnlyTheInMemoryKeyStoreUntilItIsStored() throws Exception
	{
		KeyStoreExtensions.addCertificate(keyStore, "trusted-cert", certificate);

		assertEquals(certificate, KeyStoreExtensions.getCertificate(keyStore, "trusted-cert"));
		assertFalse(reloadKeyStore().containsAlias("trusted-cert"));

		KeyStoreExtensions.store(keyStore, keystoreFile, PASSWORD);

		assertTrue(reloadKeyStore().containsAlias("trusted-cert"));
	}

	/**
	 * Test method for
	 * {@link KeyStoreExtensions#addPrivateKey(KeyStore, String, PrivateKey, char[], Certificate[])},
	 * adding a private key only changes the in memory keystore until it is stored
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	void addPrivateKey_changesOnlyTheInMemoryKeyStoreUntilItIsStored() throws Exception
	{
		KeyStoreExtensions.addPrivateKey(keyStore, ALIAS, keyPair.getPrivate(),
			PASSWORD.toCharArray(), new Certificate[] { certificate });

		assertEquals(keyPair.getPrivate(),
			KeyStoreExtensions.getPrivateKey(keyStore, ALIAS, PASSWORD.toCharArray()));
		assertFalse(reloadKeyStore().containsAlias(ALIAS));

		KeyStoreExtensions.store(keyStore, keystoreFile, PASSWORD.toCharArray());

		assertTrue(reloadKeyStore().containsAlias(ALIAS));
	}

	/**
	 * Test method for
	 * {@link KeyStoreExtensions#setKeyEntry(KeyStore, String, Key, char[], Certificate[])}
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	void setKeyEntry_assignsTheKeyToTheGivenAlias() throws Exception
	{
		KeyStoreExtensions.setKeyEntry(keyStore, ALIAS, keyPair.getPrivate(),
			PASSWORD.toCharArray(), new Certificate[] { certificate });
		KeyStoreExtensions.store(keyStore, keystoreFile, PASSWORD);

		KeyStore reloaded = reloadKeyStore();
		assertTrue(reloaded.isKeyEntry(ALIAS));
		assertEquals(keyPair.getPrivate(),
			KeyStoreExtensions.getPrivateKey(reloaded, ALIAS, PASSWORD.toCharArray()));
	}

	/**
	 * Test method for {@link KeyStoreExtensions#deleteAlias(File, String, String)}
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	void deleteAlias_removesTheEntryFromTheKeystoreFile() throws Exception
	{
		KeyStoreExtensions.addAndStoreCertificate(keyStore, keystoreFile, PASSWORD, "trusted-cert",
			certificate);
		assertTrue(reloadKeyStore().containsAlias("trusted-cert"));

		KeyStoreExtensions.deleteAlias(keystoreFile, "trusted-cert", PASSWORD);

		KeyStore reloaded = reloadKeyStore();
		assertFalse(reloaded.containsAlias("trusted-cert"));
		assertNull(KeyStoreExtensions.getCertificate(reloaded, "trusted-cert"));
	}

	/**
	 * Test method for {@link KeyStoreExtensions#store(KeyStore, File, char[])}, the stored keystore
	 * has to be protected with the given password
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	void store_withCharArrayPassword_protectsTheKeystoreWithThatPassword() throws Exception
	{
		KeyStoreExtensions.addCertificate(keyStore, "trusted-cert", certificate);
		KeyStoreExtensions.store(keyStore, keystoreFile, PASSWORD.toCharArray());

		assertNotNull(reloadKeyStore());
		assertTrue(
			KeystoreVerifier.isKeystoreFile(keystoreFile, PASSWORD, KeystoreType.JKS.name()));
	}
}
