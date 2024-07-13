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
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.Month;
import java.time.ZoneId;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.factory.CertFactory;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.factory.KeyStoreFactory;
import io.github.astrapi69.crypt.data.key.KeyStoreExtensions;
import io.github.astrapi69.crypt.data.model.DistinguishedNameInfo;
import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.search.PathFinder;

public class KeyToolExample
{
	public static void main(String[] args) throws Exception
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

		keystoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(), "new-keystore.jks");

		// Initialize a KeyStore and store the key pair and certificate
		keyStore = KeyStoreFactory.newKeyStore(keystoreFile, "JKS", "password");
		KeyStoreExtensions.setKeyEntry(keyStore, certificateAlias, keyPair.getPrivate(), password,
			new Certificate[] { cert });
		// Save the KeyStore to a file
		KeyStoreExtensions.store(keyStore, keystoreFile, "password");

		trustStoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"new-truststore.jks");

		// Initialize a KeyStore for the truststore and store the key pair and certificate
		trustStore = KeyStoreFactory.newKeyStore(trustStoreFile, "JKS", "password");
		KeyStoreExtensions.setKeyEntry(trustStore, certificateAlias, keyPair.getPrivate(), password,
			new Certificate[] { cert });
		// Save the KeyStore to a file
		KeyStoreExtensions.store(trustStore, trustStoreFile, "password");

	}

}
