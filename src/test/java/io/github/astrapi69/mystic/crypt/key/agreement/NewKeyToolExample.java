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
package io.github.astrapi69.mystic.crypt.key.agreement;

import java.io.File;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
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

import io.github.astrapi69.collection.array.ArrayFactory;
import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.key.KeyType;
import io.github.astrapi69.crypt.data.factory.CertFactory;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.factory.KeyStoreFactory;
import io.github.astrapi69.crypt.data.key.KeyInfoExtensions;
import io.github.astrapi69.crypt.data.model.DistinguishedNameInfo;
import io.github.astrapi69.crypt.data.model.ExtensionInfo;
import io.github.astrapi69.crypt.data.model.KeyInfo;
import io.github.astrapi69.crypt.data.model.KeyPairInfo;
import io.github.astrapi69.crypt.data.model.KeyStoreInfo;
import io.github.astrapi69.crypt.data.model.Validity;
import io.github.astrapi69.crypt.data.model.X509CertificateV1Info;
import io.github.astrapi69.crypt.data.model.X509CertificateV3Info;
import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.create.FileInfo;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.mystic.crypt.ssl.KeyStoreExtensions;

public class NewKeyToolExample
{
	public static void main(String[] args) throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		DistinguishedNameInfo distinguishedNameInfo;
		KeyPairInfo keyPairInfo;
		KeyStoreInfo keyStoreInfo;
		char[] password;
		X509Certificate certificate;
		KeyPair keyPair;
		File keystoreFile;
		FileInfo keystoreFileInfo;
		File trustStoreFile;
		FileInfo trustStoreFileInfo;
		String certificateAlias;

		certificateAlias = "serverKey";

		password = "password".toCharArray();
		Security.addProvider(new BouncyCastleProvider());

		keystoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(), "new-keystore.jks");

		distinguishedNameInfo = DistinguishedNameInfo.builder().commonName("Test Server")
			.countryCode("GB").location("London").organisation("My Company")
			.organisationUnit("IT Department").state("Greater London").build();

		keyPairInfo = KeyPairInfo.builder().algorithm("RSA").keySize(2048).build();
		keystoreFileInfo = FileInfo.toFileInfo(keystoreFile);

		keyStoreInfo = KeyStoreInfo.builder().fileInfo(keystoreFileInfo).type("JKS")
			.keystorePassword(password).build();

		keyPair = KeyPairInfo.toKeyPair(keyPairInfo);
		ExtensionInfo[] extensionInfos = ArrayFactory.newArray(ExtensionInfo.builder()
			.extensionId("1.3.6.1.5.5.7.3.2").critical(false).value("foo bar").build());

		X509CertificateV1Info x509CertificateV1Info = X509CertificateV1Info.builder()
			.keyPairInfo(keyPairInfo).issuer(distinguishedNameInfo)
			.serial(new BigInteger(160, new SecureRandom()))
			.validity(Validity.builder().notBefore(ZonedDateTime.parse("2023-12-01T00:00:00Z"))
				.notAfter(ZonedDateTime.parse("2025-01-01T00:00:00Z")).build())
			.subject(distinguishedNameInfo).signatureAlgorithm("SHA256withRSA").build();

		X509CertificateV3Info x509CertificateV3Info = X509CertificateV3Info.builder()
			.certificateV1Info(x509CertificateV1Info).extensions(extensionInfos).build();

		certificate = CertFactory.newX509CertificateV3(x509CertificateV3Info);

		KeyInfo privateKeyModel = KeyInfo.builder().keyType(KeyType.PRIVATE_KEY.getDisplayValue())
			.encoded(keyPair.getPrivate().getEncoded())
			.algorithm(keyPair.getPrivate().getAlgorithm()).build();

		PrivateKey privateKey = KeyInfoExtensions.toPrivateKey(privateKeyModel);
		// Initialize a KeyStore and store the key pair and certificate
		KeyStore keyStore = KeyStoreFactory.newKeystoreAndSaveForSsl(keyStoreInfo, privateKey,
			certificate, certificateAlias, password);

		trustStoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"new-truststore.jks");

		trustStoreFileInfo = FileInfo.toFileInfo(trustStoreFile);

		KeyStoreInfo trustStoreInfo = KeyStoreInfo.builder().fileInfo(trustStoreFileInfo)
			.type("JKS").keystorePassword(password).build();

		// Initialize a KeyStore for the truststore and store the key pair and certificate
		KeyStoreFactory.newKeystoreAndSaveForSsl(trustStoreInfo, privateKey, certificate,
			certificateAlias, password);

	}

}
