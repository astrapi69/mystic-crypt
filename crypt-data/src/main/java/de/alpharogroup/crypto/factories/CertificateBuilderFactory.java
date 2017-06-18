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

import java.math.BigInteger;
import java.security.PublicKey;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;

import lombok.experimental.UtilityClass;

/**
 * The factory class {@link CertificateBuilderFactory} holds methods for
 * creating CertificateBuilder.
 */
@UtilityClass
public class CertificateBuilderFactory {

	/**
	 * Factory method for creating a new {@link X509v1CertificateBuilder} object
	 * of version 1 of X.509 from the given parameters.
	 *
	 * @param issuer
	 *            X500Name representing the issuer of this certificate.
	 * @param serial
	 *            the serial number for the certificate.
	 * @param notBefore
	 *            date before which the certificate is not valid.
	 * @param notAfter
	 *            date after which the certificate is not valid.
	 * @param subject
	 *            X500Name representing the subject of this certificate.
	 * @param publicKey
	 *            the public key to be associated with the certificate.
	 * @return the new {@link X509v3CertificateBuilder} object
	 */
	public static X509v1CertificateBuilder newX509v1CertificateBuilder(X500Name issuer, BigInteger serial,
			Date notBefore, Date notAfter, X500Name subject, PublicKey publicKey) {
		final X509v1CertificateBuilder certBuilder = new JcaX509v1CertificateBuilder(issuer, serial, notBefore,
				notAfter, subject, publicKey);
		return certBuilder;
	}

	/**
	 * Factory method for creating a new {@link X509v3CertificateBuilder} object
	 * of version 3 of X.509 from the given parameters.
	 *
	 * @param issuer
	 *            X500Name representing the issuer of this certificate.
	 * @param serial
	 *            the serial number for the certificate.
	 * @param notBefore
	 *            date before which the certificate is not valid.
	 * @param notAfter
	 *            date after which the certificate is not valid.
	 * @param subject
	 *            X500Name representing the subject of this certificate.
	 * @param publicKeyInfo
	 *            the info structure for the public key to be associated with
	 *            this certificate.
	 * @return the new {@link X509v3CertificateBuilder} object
	 */
	public static X509v3CertificateBuilder newX509v3CertificateBuilder(X500Name issuer, BigInteger serial,
			Date notBefore, Date notAfter, X500Name subject, SubjectPublicKeyInfo publicKeyInfo) {
		final X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, serial, notBefore, notAfter,
				subject, publicKeyInfo);
		return certBuilder;
	}
}
