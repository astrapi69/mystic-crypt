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
