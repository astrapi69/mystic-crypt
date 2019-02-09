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
package de.alpharogroup.crypto.key.writer;

import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDate;
import java.time.Month;
import java.time.ZoneId;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.HashAlgorithm;
import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.algorithm.UnionWord;
import de.alpharogroup.crypto.factories.CertFactory;
import de.alpharogroup.crypto.key.KeyFileFormat;
import de.alpharogroup.crypto.key.reader.CertificateReader;
import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.crypto.key.reader.PublicKeyReader;
import de.alpharogroup.file.delete.DeleteFileExtensions;
import de.alpharogroup.file.search.PathFinder;
import de.alpharogroup.random.RandomExtensions;

/**
 * The unit test class for the class {@link CertificateWriter}
 */
public class CertificateWriterTest
{

	PrivateKey actual;

	X509Certificate cert;

	File derDir;

	File pemDir;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 * 
	 * @throws IOException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws SignatureException
	 * @throws IllegalStateException
	 * @throws InvalidKeyException
	 * @throws CertificateEncodingException
	 */
	@BeforeMethod
	protected void setUp() throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchProviderException, IOException, CertificateEncodingException, InvalidKeyException,
		IllegalStateException, SignatureException
	{
		Security.addProvider(new BouncyCastleProvider());
		File privatekeyPemFile;
		PrivateKey privateKey;
		File publickeyPemFile;
		PublicKey publicKey;
		String subject;
		String issuer;
		String signatureAlgorithm;
		Date start;
		Date end;
		BigInteger serialNumber;

		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privatekeyPemFile = new File(pemDir, "private.pem");

		privateKey = PrivateKeyReader.readPemPrivateKey(privatekeyPemFile);

		publickeyPemFile = new File(pemDir, "public.pem");

		publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		subject = "CN=Test subject";
		issuer = "CN=Test issue";
		signatureAlgorithm = HashAlgorithm.SHA256.getAlgorithm() + UnionWord.With.name()
			+ KeyPairGeneratorAlgorithm.RSA.getAlgorithm();

		start = Date.from(
			LocalDate.of(2017, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		end = Date.from(
			LocalDate.of(2027, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		serialNumber = RandomExtensions.randomSerialNumber();
		// create certificate
		cert = CertFactory.newX509Certificate(publicKey, privateKey, serialNumber, subject, issuer,
			signatureAlgorithm, start, end);
		assertNotNull(cert);
	}

	/**
	 * Test method for {@link CertificateWriter} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(CertificateWriter.class);
	}

	/**
	 * Test method for {@link CertificateWriter#write(X509Certificate, File, KeyFileFormat)}
	 * 
	 * @throws IOException
	 * @throws CertificateException
	 */
	@Test
	public void testWrite() throws IOException, CertificateException
	{
		X509Certificate certificate;
		File certificateFile;
		File certificateDerFile;

		certificateFile = new File(pemDir, "certificate.cert");
		// save it ...
		CertificateWriter.write(cert, certificateFile, KeyFileFormat.PEM);

		certificate = CertificateReader.readPemCertificate(certificateFile);
		assertNotNull(certificate);

		DeleteFileExtensions.delete(certificateFile);

		// ======================================================================================

		certificateDerFile = new File(derDir, "certificate.der");
		// save it ...
		CertificateWriter.write(cert, certificateDerFile, KeyFileFormat.DER);

		certificate = CertificateReader.readCertificate(certificateDerFile);
		assertNotNull(certificate);

		DeleteFileExtensions.delete(certificateDerFile);
	}

	/**
	 * Test method for {@link CertificateWriter#writeInDerFormat(X509Certificate, File)}
	 * 
	 * @throws CertificateException
	 *             is thrown if no Provider supports a CertificateFactorySpi implementation for the
	 *             specified type.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	public void testWriteInDerFormatX509CertificateFile() throws IOException, CertificateException
	{
		X509Certificate certificate;
		File certificateDerFile;

		certificateDerFile = new File(derDir, "certificate.der");
		// save it ...
		CertificateWriter.writeInDerFormat(cert, certificateDerFile);

		certificate = CertificateReader.readCertificate(certificateDerFile);
		assertNotNull(certificate);

		DeleteFileExtensions.delete(certificateDerFile);
	}

	/**
	 * Test method for {@link CertificateWriter#writeInPemFormat(X509Certificate, File)}
	 * 
	 * @throws CertificateException
	 *             is thrown if no Provider supports a CertificateFactorySpi implementation for the
	 *             specified type.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	public void testWriteInPemFormatX509CertificateFile() throws IOException, CertificateException
	{
		X509Certificate certificate;
		File certificateFile;

		certificateFile = new File(pemDir, "certificate.cert");
		// save it ...
		CertificateWriter.writeInPemFormat(cert, certificateFile);

		certificate = CertificateReader.readPemCertificate(certificateFile);
		assertNotNull(certificate);

		DeleteFileExtensions.delete(certificateFile);
	}

}
