package de.alpharogroup.crypto.factories;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.algorithm.HashAlgorithm;
import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;

/**
 * Test class for the class {@link CertFactory}.
 */
public class CertFactoryTest
{

	/**
	 * Test method for {@link CertFactory#newX509Certificate(PublicKey, PrivateKey, String, String, String, Date, Date)}.
	 */
	@Test
	public void testNewX509CertificatePublicKeyPrivateKeyStringStringStringDateDate() throws Exception
	{
		final KeyPair keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, 2048);

		final PrivateKey privateKey = keyPair.getPrivate();

		final PublicKey publicKey = keyPair.getPublic();
		final String subject = "CN=Test subject";
		final String issuer = "CN=Test issue";
		final String signatureAlgorithm = HashAlgorithm.SHA256.getAlgorithm() + CryptConst.WITH +
			 KeyPairGeneratorAlgorithm.RSA.getAlgorithm();
		final Date start = new Date(System.currentTimeMillis());
		final Date end = new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 100));

		final X509Certificate cert = CertFactory
			.newX509Certificate(publicKey, privateKey,
				subject, issuer,
				signatureAlgorithm,
				start, end);
		AssertJUnit.assertNotNull(cert);
	}

}
