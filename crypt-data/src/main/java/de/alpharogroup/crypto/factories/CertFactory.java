/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto.factories;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import de.alpharogroup.crypto.provider.SecurityProvider;
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
	 * 
	 * @throws SignatureException
	 *             is thrown if a generic signature error occur
	 * @throws NoSuchAlgorithmException
	 *             is thrown if a SecureRandomSpi implementation for the specified algorithm is not
	 *             available from the specified provider
	 * @throws IllegalStateException
	 *             is thrown if an illegal state occurs on the generation process
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cypher object fails on the generation process
	 * @throws CertificateEncodingException
	 *             is thrown whenever an error occurs while attempting to encode a certificate
	 */
	public static X509Certificate newX509Certificate(final PublicKey publicKey,
		final PrivateKey privateKey, final BigInteger serialNumber, final String subject,
		final String issuer, final String signatureAlgorithm, final Date start, final Date end)
		throws CertificateEncodingException, InvalidKeyException, IllegalStateException,
		NoSuchAlgorithmException, SignatureException

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

	/**
	 * Factory method for creating a new {@link X509Certificate} object of the first version of
	 * X.509 from the given parameters.
	 *
	 * SecurityProvider is Bouncy Castle.
	 *
	 * @param keyPair
	 *            the key pair
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
	 *
	 * @param signatureAlgorithm
	 *            the signature algorithm i.e 'SHA1withRSA'
	 * @return the new {@link X509Certificate} object
	 * 
	 * @throws OperatorCreationException
	 *             is thrown if a security error occur on creation of {@link ContentSigner}
	 * @throws CertificateException
	 *             if the conversion is unable to be made
	 */
	public static X509Certificate newX509CertificateV1(KeyPair keyPair, X500Name issuer,
		BigInteger serial, Date notBefore, Date notAfter, X500Name subject,
		String signatureAlgorithm) throws OperatorCreationException, CertificateException
	{
		X509v1CertificateBuilder certBuilder = new JcaX509v1CertificateBuilder(issuer, serial,
			notBefore, notAfter, subject, keyPair.getPublic());
		ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
			.setProvider(SecurityProvider.BC.name()).build(keyPair.getPrivate());
		X509Certificate x509Certificate = new JcaX509CertificateConverter()
			.setProvider(SecurityProvider.BC.name()).getCertificate(certBuilder.build(signer));
		return x509Certificate;
	}

	/**
	 * Factory method for creating a new intermediate {@link X509Certificate} object of version 3 of
	 * X.509 from the given parameters that can be used to sign other certificates.
	 *
	 * @param keyPair
	 *            the key pair
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
	 * @param signatureAlgorithm
	 *            the signature algorithm i.e 'SHA1withRSA'
	 * @param caCert
	 *            the v1 ca certificate
	 * @return the {@link X509Certificate} object
	 * 
	 * @throws NoSuchAlgorithmException
	 *             is thrown if a SecureRandomSpi implementation for the specified algorithm is not
	 *             available from the specified provider
	 * @throws CertIOException
	 *             is thrown in the cert package and its sub-packages.
	 * @throws OperatorCreationException
	 *             is thrown if a security error occur on creation of {@link ContentSigner}
	 * @throws CertificateException
	 *             if the conversion is unable to be made
	 */
	public static X509Certificate newIntermediateX509CertificateV3(KeyPair keyPair, X500Name issuer,
		BigInteger serial, Date notBefore, Date notAfter, X500Name subject,
		String signatureAlgorithm, X509Certificate caCert) throws NoSuchAlgorithmException,
		CertIOException, OperatorCreationException, CertificateException
	{
		X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serial,
			notBefore, notAfter, subject, keyPair.getPublic());

		JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
			extensionUtils.createAuthorityKeyIdentifier(caCert));
		certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
			extensionUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
		certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
		certBuilder.addExtension(Extension.keyUsage, true,
			new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign));
		ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
			.setProvider(SecurityProvider.BC.name()).build(keyPair.getPrivate());
		return new JcaX509CertificateConverter().setProvider(SecurityProvider.BC.name())
			.getCertificate(certBuilder.build(signer));
	}

	/**
	 * Factory method for creating a new intermediate {@link X509Certificate} object of version 3 of
	 * X.509 from the given parameters that can be used as an end entity certificate.
	 *
	 * @param keyPair
	 *            the key pair
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
	 * @param signatureAlgorithm
	 *            the signature algorithm i.e 'SHA1withRSA'
	 * @param caCert
	 *            the ca cert
	 * @return the {@link X509Certificate} object
	 * 
	 * @throws NoSuchAlgorithmException
	 *             is thrown if a SecureRandomSpi implementation for the specified algorithm is not
	 *             available from the specified provider.
	 * @throws CertIOException
	 *             is thrown in the cert package and its sub-packages.
	 * @throws OperatorCreationException
	 *             is thrown if a security error occur on creation of {@link ContentSigner}
	 * @throws CertificateException
	 *             if the conversion is unable to be made
	 */
	public static X509Certificate newEndEntityX509CertificateV3(KeyPair keyPair, X500Name issuer,
		BigInteger serial, Date notBefore, Date notAfter, X500Name subject,
		String signatureAlgorithm, X509Certificate caCert) throws NoSuchAlgorithmException,
		CertIOException, OperatorCreationException, CertificateException
	{
		X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serial,
			notBefore, notAfter, subject, keyPair.getPublic());

		JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
		certBuilder.addExtension(Extension.authorityKeyIdentifier, false,
			extensionUtils.createAuthorityKeyIdentifier(caCert));
		certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
			extensionUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
		certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
		certBuilder.addExtension(Extension.keyUsage, true,
			new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
		ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
			.setProvider(SecurityProvider.BC.name()).build(keyPair.getPrivate());
		return new JcaX509CertificateConverter().setProvider(SecurityProvider.BC.name())
			.getCertificate(certBuilder.build(signer));
	}

}
