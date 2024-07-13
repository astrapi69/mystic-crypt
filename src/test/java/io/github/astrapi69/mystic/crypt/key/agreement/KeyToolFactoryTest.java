package io.github.astrapi69.mystic.crypt.key.agreement;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.Month;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.collection.array.ArrayFactory;
import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.factory.CertFactory;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.factory.KeyStoreFactory;
import io.github.astrapi69.crypt.data.key.KeyStoreExtensions;
import io.github.astrapi69.crypt.data.model.DistinguishedNameInfo;
import io.github.astrapi69.crypt.data.model.ExtensionInfo;
import io.github.astrapi69.crypt.data.model.KeyPairInfo;
import io.github.astrapi69.crypt.data.model.KeyStoreInfo;
import io.github.astrapi69.crypt.data.model.Validity;
import io.github.astrapi69.crypt.data.model.X509CertificateV1Info;
import io.github.astrapi69.crypt.data.model.X509CertificateV3Info;
import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.create.FileInfo;
import io.github.astrapi69.file.delete.DeleteFileExtensions;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.random.number.RandomBigIntegerFactory;

/**
 * The class {@code KeyToolFactoryTest} provides unit tests for creating keystores and truststores
 * with the help of various cryptographic models and utilities.
 */
public class KeyToolFactoryTest
{

	/**
	 * Test method for creating a keystore and a truststore using {@link KeyStoreInfo},
	 * {@link KeyPairInfo}, and other related objects.
	 *
	 * @throws Exception
	 *             if any error occurs during the creation or saving of keystores
	 */
	@Test
	public void testCreateKeyStoreAndTrustStoreWithInfoObjects() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		DistinguishedNameInfo distinguishedNameInfo;
		KeyPairInfo keyPairInfo;
		KeyStoreInfo keyStoreInfo;
		char[] password;
		BigInteger serial;
		KeyPair keyPair;
		PrivateKey privateKey;
		X509Certificate certificate;
		File keystoreFile;
		FileInfo keystoreFileInfo;
		File trustStoreFile;
		FileInfo trustStoreFileInfo;
		String certificateAlias;
		ExtensionInfo[] extensionInfos;

		certificateAlias = "serverKey";
		password = "password".toCharArray();

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

		privateKey = keyPair.getPrivate();

		// Initialize a KeyStore and store the key pair and certificate
		keystoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(), "ssl-keystore.jks");
		keystoreFileInfo = FileInfo.toFileInfo(keystoreFile);
		keyStoreInfo = KeyStoreInfo.builder().fileInfo(keystoreFileInfo).type("JKS")
			.keystorePassword(password).build();
		KeyStoreFactory.newKeystoreAndSaveForSsl(keyStoreInfo, privateKey, certificate,
			certificateAlias, password);

		// Initialize a KeyStore for the truststore and store the key pair and certificate
		trustStoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"ssl-truststore.jks");
		trustStoreFileInfo = FileInfo.toFileInfo(trustStoreFile);
		KeyStoreInfo trustStoreInfo = KeyStoreInfo.builder().fileInfo(trustStoreFileInfo)
			.type("JKS").keystorePassword(password).build();
		KeyStoreFactory.newKeystoreAndSaveForSsl(trustStoreInfo, privateKey, certificate,
			certificateAlias, password);
		// comment if you want to check with SecureServer and SecureClient
		DeleteFileExtensions.delete(keystoreFile);
		DeleteFileExtensions.delete(trustStoreFile);
	}

	/**
	 * Test method for creating a keystore and a truststore without using {@link KeyStoreInfo},
	 * {@link KeyPairInfo}, and other related objects.
	 *
	 * @throws Exception
	 *             if any error occurs during the creation or saving of keystores
	 */
	@Test
	public void testCreateKeyStoreAndTrustStore() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		KeyPair keyPair;
		org.bouncycastle.asn1.x500.X500Name issuer;
		BigInteger serial;
		Date notBefore;
		Date notAfter;
		X500Name subject;
		String signatureAlgorithm;
		X509Certificate cert;
		String distinguishedName;
		char[] password;
		DistinguishedNameInfo distinguishedNameInfo;
		String certificateAlias;
		File keystoreFile;
		KeyStore keyStore;
		KeyStore trustStore;
		File trustStoreFile;

		certificateAlias = "serverKey";
		password = "password".toCharArray();

		distinguishedNameInfo = DistinguishedNameInfo.builder().commonName("Tyler Durden")
			.countryCode("GR").location("Katerini").organisation("Cool Company")
			.organisationUnit("IT Department").state("Macedonia").build();

		distinguishedName = distinguishedNameInfo.toRepresentableString();
		serial = BigInteger.ONE;
		notBefore = Date.from(
			LocalDate.of(2024, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		notAfter = Date.from(
			LocalDate.of(2034, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		subject = new X500Name(distinguishedName);
		signatureAlgorithm = "SHA256withRSA";
		issuer = new X500Name(distinguishedName);

		// Generate a key pair
		keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, 2048);

		// Create a self-signed certificate
		cert = CertFactory.newX509CertificateV3(keyPair, issuer, serial, notBefore, notAfter,
			subject, signatureAlgorithm);

		keystoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(), "ssl-keystore.jks");

		// Initialize a KeyStore and store the key pair and certificate
		keyStore = KeyStoreFactory.newKeyStore(keystoreFile, "JKS", "password");
		KeyStoreExtensions.setKeyEntry(keyStore, certificateAlias, keyPair.getPrivate(), password,
			new Certificate[] { cert });
		// Save the KeyStore to a file
		KeyStoreExtensions.store(keyStore, keystoreFile, "password");

		trustStoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"ssl-truststore.jks");

		// Initialize a KeyStore for the truststore and store the key pair and certificate
		trustStore = KeyStoreFactory.newKeyStore(trustStoreFile, "JKS", "password");
		KeyStoreExtensions.setKeyEntry(trustStore, certificateAlias, keyPair.getPrivate(), password,
			new Certificate[] { cert });
		// Save the KeyStore to a file
		KeyStoreExtensions.store(trustStore, trustStoreFile, "password");
		// comment if you want to check with SecureServer and SecureClient
		DeleteFileExtensions.delete(keystoreFile);
		DeleteFileExtensions.delete(trustStoreFile);
	}

}
