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

import static io.github.benas.randombeans.api.EnhancedRandom.random;
import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.reader.PublicKeyReader;
import de.alpharogroup.date.CalculateDateExtensions;
import de.alpharogroup.file.search.PathFinder;

/**
 * The class {@link CertificateBuilderFactory}
 */
public class CertificateBuilderFactoryTest
{

	/**
	 * Test method for
	 * {@link CertificateBuilderFactory#newX509v1CertificateBuilder(X500Name, BigInteger, Date, Date, X500Name, PublicKey)}
	 */
	@Test
	public void testNewX509v1CertificateBuilder() throws Exception
	{
		final File keyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File publickeyPemFile = new File(keyPemDir, "public.pem");

		Security.addProvider(new BouncyCastleProvider());

		final PublicKey publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		X500Name issuer = new X500Name("C=DE");
		BigInteger serial = random(BigInteger.class);

		Date notBefore = new Date();
		Date notAfter = CalculateDateExtensions.addYears(notBefore, 10);
		X500Name subject = new X500Name("O=foo-company");

		X509v1CertificateBuilder certificateBuilder = CertificateBuilderFactory
			.newX509v1CertificateBuilder(issuer, serial, notBefore, notAfter, subject, publicKey);

		assertNotNull(certificateBuilder);
	}

	/**
	 * Test method for
	 * {@link CertificateBuilderFactory#newX509v3CertificateBuilder(X500Name, BigInteger, Date, Date, X500Name, SubjectPublicKeyInfo)}
	 */
	@Test
	public void testNewX509v3CertificateBuilder() throws Exception
	{
		final File keyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File publickeyPemFile = new File(keyPemDir, "public.pem");

		Security.addProvider(new BouncyCastleProvider());

		final PublicKey publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		X500Name issuer = new X500Name("C=DE");
		BigInteger serial = random(BigInteger.class);

		Date notBefore = new Date();
		Date notAfter = CalculateDateExtensions.addYears(notBefore, 10);
		X500Name subject = new X500Name("O=foo-company");

		SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo
			.getInstance(publicKey.getEncoded());

		X509v3CertificateBuilder certificateBuilder = CertificateBuilderFactory
			.newX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, subject,
				publicKeyInfo);

		assertNotNull(certificateBuilder);
	}
	
	/**
	 * Test method for {@link CertificateBuilderFactory} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(CertificateBuilderFactory.class);
	}

}
