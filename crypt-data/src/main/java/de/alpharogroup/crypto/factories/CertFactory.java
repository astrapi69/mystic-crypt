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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.x509.X509V3CertificateGenerator;

import lombok.experimental.UtilityClass;

/**
 * The factory class {@link CertFactory} holds methods for creating {@link Certificate} objects and
 * sub classes like {@link X509Certificate}.
 */
@SuppressWarnings("deprecation")
@UtilityClass
public class CertFactory
{

	/**
	 * Factory method for creating a new {@link X509Certificate} from the given certificate type and
	 * certificate data as byte array.
	 *
	 *
	 * @param type
	 *            the certificate type
	 * @param certificateData
	 *            the certificate data as byte array
	 * @return the new {@link X509Certificate}
	 * @throws CertificateException
	 *             is thrown if no Provider supports a CertificateFactorySpi implementation for the
	 *             given certificate type.
	 */
	public static X509Certificate newX509Certificate(final String type,
		final byte[] certificateData) throws CertificateException
	{
		final CertificateFactory cf = CertificateFactory.getInstance(type);
		final InputStream inputStream = new ByteArrayInputStream(certificateData);
		final X509Certificate certificate = (X509Certificate)cf.generateCertificate(inputStream);
		return certificate;
	}

	/**
	 * Factory method for creating a new {@link X509Certificate} object from the given parameters.
	 *
	 * @param publicKey
	 *            the public key
	 * @param privateKey
	 *            the private key
	 * @param serialNumber
	 *            the serial number
	 * @param subject
	 *            the subject
	 * @param issuer
	 *            the issuer
	 * @param signatureAlgorithm
	 *            the signature algorithm
	 * @param start
	 *            the start
	 * @param end
	 *            the end
	 * @return the new {@link X509Certificate} object
	 * @throws Exception
	 *             is thrown if if a security error occur
	 */
	public static X509Certificate newX509Certificate(final PublicKey publicKey,
		final PrivateKey privateKey, final BigInteger serialNumber, final String subject, final String issuer,
		final String signatureAlgorithm, final Date start, final Date end) throws Exception
	{
		final X500Principal subjectPrincipal = new X500Principal(subject);
		final X500Principal issuerPrincipal = new X500Principal(issuer);
		final X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
		certificateGenerator.setPublicKey(publicKey);
		certificateGenerator.setSerialNumber(serialNumber);
		certificateGenerator.setSubjectDN(subjectPrincipal);
		certificateGenerator.setIssuerDN(issuerPrincipal);
		certificateGenerator.setNotBefore(start);
		certificateGenerator.setNotAfter(end);
		certificateGenerator.setSignatureAlgorithm(signatureAlgorithm);
		final X509Certificate certificate = certificateGenerator.generate(privateKey);
		return certificate;
	}

}
