package io.github.astrapi69.mystic.crypt.key.agreement;

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

public class TestKeyAgreementWithSSLandTLS
{

	@Test
	public void testKeyAgreementWithSSLandTLS()
		throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException,
		UnrecoverableKeyException, KeyManagementException
	{
		// Step 2: Load KeyStore and TrustStore
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(new FileInputStream("keystore.jks"), "password".toCharArray());

		KeyStore trustStore = KeyStore.getInstance("JKS");
		trustStore.load(new FileInputStream("truststore.jks"), "password".toCharArray());
		// Step 3: Initialize KeyManagerFactory and TrustManagerFactory
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
		kmf.init(keyStore, "password".toCharArray());

		TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
		tmf.init(trustStore);
		// Step 4: Initialize SSLContext
		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
		// Step 5: Use SSLContext for Secure Communication


	}
}
