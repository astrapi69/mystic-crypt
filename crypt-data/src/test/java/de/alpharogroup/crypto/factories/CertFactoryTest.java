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

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.Month;
import java.time.ZoneId;
import java.util.Date;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.algorithm.HashAlgorithm;
import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.key.reader.CertificateReader;
import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.crypto.key.reader.PublicKeyReader;
import de.alpharogroup.crypto.key.writer.CertificateWriter;
import de.alpharogroup.file.delete.DeleteFileExtensions;
import de.alpharogroup.file.search.PathFinder;
import de.alpharogroup.random.RandomExtensions;

/**
 * The unit test class for the class {@link CertFactory}
 */
public class CertFactoryTest
{

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeMethod
	protected void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Test method for
	 * {@link CertFactory#newX509Certificate(PublicKey, PrivateKey, String, String, String, Date, Date)}
	 */
	@Test
	public void testNewX509CertificatePublicKeyPrivateKeyStringStringStringDateDate()
		throws Exception
	{
		final File privatekeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File privatekeyPemFile = new File(privatekeyPemDir, "private.pem");

		final PrivateKey privateKey = PrivateKeyReader.readPemPrivateKey(privatekeyPemFile);


		final File publickeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File publickeyPemFile = new File(publickeyPemDir, "public.pem");

		Security.addProvider(new BouncyCastleProvider());

		final PublicKey publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		final String subject = "CN=Test subject";
		final String issuer = "CN=Test issue";
		final String signatureAlgorithm = HashAlgorithm.SHA256.getAlgorithm() + CryptConst.WITH
			+ KeyPairGeneratorAlgorithm.RSA.getAlgorithm();

		final Date start = Date.from(
			LocalDate.of(2017, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		final Date end = Date.from(
			LocalDate.of(2027, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		final BigInteger serialNumber = RandomExtensions.randomSerialNumber();
		// create certificate
		final X509Certificate cert = CertFactory.newX509Certificate(publicKey, privateKey,
			serialNumber, subject, issuer, signatureAlgorithm, start, end);
		assertNotNull(cert);

		final File pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File certificateFile = new File(pemDir, "certificate.cert");
		// save it ...
		CertificateWriter.writeInPemFormat(cert, certificateFile);
		// read it ...
		final X509Certificate certificate = CertificateReader.readPemCertificate(certificateFile);
		// check null
		assertNotNull(certificate);
		// check equal
		assertEquals(cert, certificate);

		DeleteFileExtensions.delete(certificateFile);
	}

	/**
	 * Test method for
	 * {@link CertFactory#newX509CertificateV1(KeyPair, X500Name, BigInteger, Date, Date, X500Name, String)}
	 */
	@Test
	public void testNewX509CertificateV1() throws Exception
	{
		final KeyPair keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, 2048);
		final X500Name issuer = new X500Name("CN=Issuer of this certificate");
		final BigInteger serial = BigInteger.ONE;
		final Date notBefore = Date.from(
			LocalDate.of(2017, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		final Date notAfter = Date.from(
			LocalDate.of(2027, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		final X500Name subject = new X500Name("CN=Subject of this certificate");
		final String signatureAlgorithm = "SHA1withRSA";
		final X509Certificate cert = CertFactory.newX509CertificateV1(keyPair, issuer, serial,
			notBefore, notAfter, subject, signatureAlgorithm);
		assertNotNull(cert);

	}

	/**
	 * Test method for {@link CertFactory#newX509Certificate(String, byte[])}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws CertificateException
	 *             is thrown if no Provider supports a CertificateFactorySpi implementation for the
	 *             given certificate type.
	 */
	@Test
	public void testNewX509CertificateStringByteArray() throws IOException, CertificateException
	{
		X509Certificate actual;
		String type;
		byte[] certificateData;

		final File pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File certificatePemFile = new File(pemDir, "certificate.pem");
		String base64EncodedCertificate = CertificateReader.readPemFileAsBase64(certificatePemFile);
		certificateData = new Base64().decode(base64EncodedCertificate);
		type = "X.509";
		actual = CertFactory.newX509Certificate(type, certificateData);
		assertNotNull(actual);
	}

	/**
	 * Test method for
	 * {@link CertFactory#newIntermediateX509CertificateV3(KeyPair, X500Name, BigInteger, Date, Date, X500Name, String, X509Certificate)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws CertificateException
	 *             if the conversion is unable to be made
	 * @throws NoSuchAlgorithmException
	 *             is thrown if a SecureRandomSpi implementation for the specified algorithm is not
	 *             available from the specified provider.
	 * @throws OperatorCreationException
	 *             is thrown if a security error occur on creation of {@link ContentSigner}
	 */
	@Test
	public void testNewIntermediateX509CertificateV3() throws IOException, CertificateException,
		NoSuchAlgorithmException, OperatorCreationException
	{
		X509Certificate actual;
		X509Certificate caCert;
		String type;
		byte[] certificateData;

		final File pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File certificatePemFile = new File(pemDir, "certificate.pem");
		String base64EncodedCertificate = CertificateReader.readPemFileAsBase64(certificatePemFile);
		certificateData = new Base64().decode(base64EncodedCertificate);
		type = "X.509";
		caCert = CertFactory.newX509Certificate(type, certificateData);

		final KeyPair keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, 2048);
		final X500Name issuer = new X500Name("CN=Issuer of this certificate");
		final BigInteger serial = BigInteger.ONE;
		final Date notBefore = Date.from(
			LocalDate.of(2017, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		final Date notAfter = Date.from(
			LocalDate.of(2027, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		final X500Name subject = new X500Name("CN=Subject of this certificate");
		final String signatureAlgorithm = "SHA1withRSA";
		actual = CertFactory.newIntermediateX509CertificateV3(keyPair, issuer, serial, notBefore,
			notAfter, subject, signatureAlgorithm, caCert);
		assertNotNull(actual);
	}

	/**
	 * Test method for
	 * {@link CertFactory#newEndEntityX509CertificateV3(KeyPair, X500Name, BigInteger, Date, Date, X500Name, String, X509Certificate)}
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws CertificateException
	 *             if the conversion is unable to be made
	 * @throws NoSuchAlgorithmException
	 *             is thrown if a SecureRandomSpi implementation for the specified algorithm is not
	 *             available from the specified provider.
	 * @throws OperatorCreationException
	 *             is thrown if a security error occur on creation of {@link ContentSigner}
	 */
	@Test
	public void testNewEndEntityX509CertificateV3() throws IOException, CertificateException,
		NoSuchAlgorithmException, OperatorCreationException
	{
		X509Certificate actual;
		X509Certificate caCert;
		String type;
		byte[] certificateData;

		final File pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File certificatePemFile = new File(pemDir, "certificate.pem");
		String base64EncodedCertificate = CertificateReader.readPemFileAsBase64(certificatePemFile);
		certificateData = new Base64().decode(base64EncodedCertificate);
		type = "X.509";
		caCert = CertFactory.newX509Certificate(type, certificateData);

		final KeyPair keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, 2048);
		final X500Name issuer = new X500Name("CN=Issuer of this certificate");
		final BigInteger serial = BigInteger.ONE;
		final Date notBefore = Date.from(
			LocalDate.of(2017, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		final Date notAfter = Date.from(
			LocalDate.of(2027, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		final X500Name subject = new X500Name("CN=Subject of this certificate");
		final String signatureAlgorithm = "SHA1withRSA";
		actual = CertFactory.newEndEntityX509CertificateV3(keyPair, issuer, serial, notBefore, notAfter,
			subject, signatureAlgorithm, caCert);
		assertNotNull(actual);
	}
	
	/**
	 * Test method for {@link CertFactory} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(CertFactory.class);
	}

}
