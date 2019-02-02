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
package de.alpharogroup.crypto.key.reader;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.Month;
import java.time.ZoneId;
import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.HashAlgorithm;
import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.algorithm.UnionWord;
import de.alpharogroup.crypto.factories.CertFactory;
import de.alpharogroup.crypto.key.KeyFileFormat;
import de.alpharogroup.crypto.key.writer.CertificateWriter;
import de.alpharogroup.file.delete.DeleteFileExtensions;
import de.alpharogroup.file.search.PathFinder;
import de.alpharogroup.random.RandomExtensions;

/**
 * The unit test class for the class {@link CertificateReaderTest}
 */
public class CertificateReaderTest
{

	/**
	 * Test method for {@link CertificateReader#readCertificate(File)}
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testReadDerCertificateFile() throws Exception
	{
		File derDir;
		File certificateDerFile;
		File privatekeyPemDir;
		File privatekeyPemFile;
		PrivateKey privateKey;
		File publickeyPemDir;
		File publickeyPemFile;
		PublicKey publicKey;
		String subject;
		String issuer;
		String signatureAlgorithm;
		Date start;
		Date end;
		BigInteger serialNumber;
		X509Certificate cert;
		X509Certificate certificate;
		// new scenario...
		privatekeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		privatekeyPemFile = new File(privatekeyPemDir, "private.pem");

		Security.addProvider(new BouncyCastleProvider());

		privateKey = PrivateKeyReader.readPemPrivateKey(privatekeyPemFile);

		publickeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		publickeyPemFile = new File(publickeyPemDir, "public.pem");

		Security.addProvider(new BouncyCastleProvider());

		publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		subject = "CN=Test subject";
		issuer = "CN=Test issue";
		signatureAlgorithm = HashAlgorithm.SHA256.getAlgorithm()
			+ UnionWord.With.name() + KeyPairGeneratorAlgorithm.RSA.getAlgorithm();

		start = Date.from(
			LocalDate.of(2017, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		end = Date.from(
			LocalDate.of(2027, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		serialNumber = RandomExtensions.randomSerialNumber();
		// create certificate
		cert = CertFactory.newX509Certificate(publicKey, privateKey,
			serialNumber, subject, issuer, signatureAlgorithm, start, end);
		AssertJUnit.assertNotNull(cert);

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		certificateDerFile = new File(derDir, "certificate.der");
		// save it ...
		CertificateWriter.write(cert, certificateDerFile, KeyFileFormat.DER);

		certificate = CertificateReader.readCertificate(certificateDerFile);
		AssertJUnit.assertNotNull(certificate);

		DeleteFileExtensions.delete(certificateDerFile);
	}

	/**
	 * Test method for {@link CertificateReader#readPemCertificate(File)}
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testReadPemCertificateFile() throws Exception
	{
		File pemDir;
		File certificateFile;
		File privatekeyPemDir;
		File privatekeyPemFile;
		PrivateKey privateKey;
		File publickeyPemDir;
		File publickeyPemFile;
		PublicKey publicKey;
		String subject;
		String issuer;
		String signatureAlgorithm;
		Date start;
		Date end;
		BigInteger serialNumber;
		X509Certificate cert;
		X509Certificate certificate;
				
		privatekeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		privatekeyPemFile = new File(privatekeyPemDir, "private.pem");

		Security.addProvider(new BouncyCastleProvider());

		privateKey = PrivateKeyReader.readPemPrivateKey(privatekeyPemFile);

		publickeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		publickeyPemFile = new File(publickeyPemDir, "public.pem");

		Security.addProvider(new BouncyCastleProvider());

		publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		subject = "CN=Test subject";
		issuer = "CN=Test issue";
		signatureAlgorithm = HashAlgorithm.SHA256.getAlgorithm()
			+ UnionWord.With.name() + KeyPairGeneratorAlgorithm.RSA.getAlgorithm();

		start = Date.from(
			LocalDate.of(2017, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		end = Date.from(
			LocalDate.of(2027, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		serialNumber = RandomExtensions.randomSerialNumber();
		// create certificate
		cert = CertFactory.newX509Certificate(publicKey, privateKey,
			serialNumber, subject, issuer, signatureAlgorithm, start, end);
		AssertJUnit.assertNotNull(cert);

		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		certificateFile = new File(pemDir, "certificate.cert");
		// save it ...
		CertificateWriter.write(cert, certificateFile, KeyFileFormat.PEM);

		certificate = CertificateReader.readPemCertificate(certificateFile);
		AssertJUnit.assertNotNull(certificate);

		DeleteFileExtensions.delete(certificateFile);
	}

	/**
	 * Test method for {@link CertificateReader} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(CertificateReader.class);
	}

}
