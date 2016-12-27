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
