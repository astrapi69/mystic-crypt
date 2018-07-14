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
package de.alpharogroup.crypto.key;

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.testng.AssertJUnit;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.algorithm.HashAlgorithm;
import de.alpharogroup.crypto.key.reader.CertificateReader;
import de.alpharogroup.file.search.PathFinder;

/**
 * The class {@link CertificateExtensionsTest}.
 */
public class CertificateExtensionsTest
{

	/** The certificate for tests. */
	private X509Certificate certificate;


	/**
	 * Sets up method will be invoked before every unit test method in this class.
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@BeforeMethod
	protected void setUp() throws Exception
	{
		if (certificate == null)
		{
			final File pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
			final File certificatePemFile = new File(pemDir, "certificate.pem");
			certificate = CertificateReader.readPemCertificate(certificatePemFile);
			AssertJUnit.assertNotNull(certificate);
		}
	}

	/**
	 * Test method for {@link CertificateExtensions#getCountry(X509Certificate)}.
	 *
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	@Test
	public void testGetCountry() throws CertificateEncodingException
	{
		final String expected = "";
		final String actual = CertificateExtensions.getCountry(certificate);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions#getFingerprint(X509Certificate, HashAlgorithm)}.
	 *
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 */
	@Test
	public void testGetFingerprint() throws CertificateEncodingException, NoSuchAlgorithmException
	{
		String expected = "98e12b1607890c76daa0b594be26616ceee93102";
		String actual = CertificateExtensions.getFingerprint(certificate, HashAlgorithm.SHA1);
		assertEquals(expected, actual);

		expected = "3a3dc338c7b444c3dd80e4f997d027a72451f9d5641783b3c810bf2d89bbd699";
		actual = CertificateExtensions.getFingerprint(certificate, HashAlgorithm.SHA_256);
		assertEquals(expected, actual);

		expected = "a44c1dc693670135c1abb13eb1a9472ab76059c29a7fb8b4a41ca605f3255fde7595374983ce7bc27633774d3c957026";
		actual = CertificateExtensions.getFingerprint(certificate, HashAlgorithm.SHA_384);
		assertEquals(expected, actual);

		expected = "8ea8310e1ed6f299e4de949a8094cde28bac3550bf4fd551283e346477fbba77b085adae6348df1a296b370fe56819baf4fdc31e43c42ce192cad4bbfc6829ae";
		actual = CertificateExtensions.getFingerprint(certificate, HashAlgorithm.SHA_512);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for
	 * {@link CertificateExtensions#getFirstValueOf(X509Certificate, org.bouncycastle.asn1.ASN1ObjectIdentifier)}.
	 *
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	@Test
	public void testGetFirstValueOf() throws CertificateEncodingException
	{
		final String expected = "Test subject";
		final String actual = CertificateExtensions.getFirstValueOf(certificate, BCStyle.CN);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions#getIssuedBy(X509Certificate)}.
	 */
	@Test
	public void testGetIssuedBy()
	{
		final String expected = "CN=Test subject";
		final String actual = CertificateExtensions.getIssuedBy(certificate);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions#getIssuedTo(X509Certificate)}.
	 */
	@Test
	public void testGetIssuedTo()
	{
		final String expected = "CN=Test issue";
		final String actual = CertificateExtensions.getIssuedTo(certificate);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions#getLocality(X509Certificate)}.
	 *
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	@Test
	public void testGetLocality() throws CertificateEncodingException
	{
		final String expected = "";
		final String actual = CertificateExtensions.getLocality(certificate);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions#getOrganization(X509Certificate)}.
	 *
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	@Test
	public void testGetOrganization() throws CertificateEncodingException
	{
		final String expected = "";
		final String actual = CertificateExtensions.getOrganization(certificate);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions#getSignatureAlgorithm(X509Certificate)}.
	 */
	@Test
	public void testGetSignatureAlgorithm()
	{
		final String expected = CryptConst.SHA256_WITH_RSA;
		final String actual = CertificateExtensions.getSignatureAlgorithm(certificate);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions#getValidFrom(X509Certificate)}.
	 */
	@Test
	public void testGetValidFrom()
	{
		final Date expected = Date
			.from(ZonedDateTime.of(2016, 12, 31, 23, 0, 0, 0, ZoneId.of("UTC")).toInstant());
		final Date actual = CertificateExtensions.getValidFrom(certificate);
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link CertificateExtensions#getValidUntil(X509Certificate)}.
	 */
	@Test
	public void testGetValidUntil()
	{
		final Date expected = Date
			.from(ZonedDateTime.of(2026, 12, 31, 23, 0, 0, 0, ZoneId.of("UTC")).toInstant());
		final Date actual = CertificateExtensions.getValidUntil(certificate);
		assertEquals(expected, actual);
	}

}
