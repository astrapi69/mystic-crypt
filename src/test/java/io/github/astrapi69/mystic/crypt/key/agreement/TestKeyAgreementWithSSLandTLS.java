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

// Step 1: Import Necessary Libraries

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.search.PathFinder;

public class TestKeyAgreementWithSSLandTLS
{

	@Test
	public void testKeyAgreementWithSSLandTLS()
		throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException,
		UnrecoverableKeyException, KeyManagementException
	{
		File keystoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"keystore.jks");
		File trustStoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"truststore.jks");
		// Step 2: Load KeyStore and TrustStore
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(new FileInputStream(keystoreFile), "password".toCharArray());

		KeyStore trustStore = KeyStore.getInstance("JKS");
		trustStore.load(new FileInputStream(trustStoreFile), "password".toCharArray());
		// Step 3: Initialize KeyManagerFactory and TrustManagerFactory
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(keyStore, "password".toCharArray());

		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
		tmf.init(trustStore);
		// Step 4: Initialize SSLContext
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
		// Step 5: Use SSLContext for Secure Communication
		// See the use in action of sslContext in the corresponding classes SecureServer and
		// SecureClient
	}
}
