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
package io.github.astrapi69.crypto.sign;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.Month;
import java.time.ZoneId;
import java.util.Date;

import org.testng.annotations.Test;

import de.alpharogroup.file.search.PathFinder;
import de.alpharogroup.random.number.RandomBigIntegerFactory;
import io.github.astrapi69.crypto.compound.CompoundAlgorithm;
import io.github.astrapi69.crypto.factories.CertFactory;
import io.github.astrapi69.crypto.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypto.key.reader.PublicKeyReader;

/**
 * The unit test class for the class {@link DigitalSignaturesExtensions}
 */
public class DigitalSignaturesExtensionsTest
{

	/**
	 * Test chained encrypt and decrypt with
	 * {@link DigitalSignaturesExtensions#sign(PrivateKey, String, String, byte[])}
	 * {@link DigitalSignaturesExtensions#verify(Certificate, String, String, byte[], byte[])}
	 *
	 * @throws Exception
	 *             is thrown if any security exception occured
	 */
	@Test
	public void testSignAndVerifyWithCertificate() throws Exception
	{
		boolean actual;
		boolean expected;
		String value;
		String subject;
		String issuer;
		String signatureAlgorithm;
		Charset charset;
		Date start;
		Date end;
		BigInteger serialNumber;
		X509Certificate cert;
		File publickeyDerDir;
		File publickeyDerFile;
		File privatekeyDerFile;
		PrivateKey privateKey;
		PublicKey publicKey;

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "/der");
		publickeyDerFile = new File(publickeyDerDir, "public.der");
		privatekeyDerFile = new File(publickeyDerDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);

		charset = StandardCharsets.UTF_8;
		value = new String(
			"Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)".getBytes(charset),
			charset);

		byte[] signedWithMessageDigest = DigitalSignaturesExtensions.sign(privateKey, "SHA-256",
			"RSA", value.getBytes(charset));

		subject = "CN=Test subject";
		issuer = "CN=Test issue";

		start = Date.from(
			LocalDate.of(2020, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		end = Date.from(
			LocalDate.of(2030, Month.JANUARY, 1).atStartOfDay(ZoneId.systemDefault()).toInstant());
		serialNumber = RandomBigIntegerFactory.randomSerialNumber();
		signatureAlgorithm = CompoundAlgorithm.SHA256_WITH_RSA.getAlgorithm(); // SHA256withRSA
		cert = CertFactory.newX509Certificate(publicKey, privateKey, serialNumber, subject, issuer,
			signatureAlgorithm, start, end);

		actual = DigitalSignaturesExtensions.verify(cert, "SHA-256", "RSA", value.getBytes(charset),
			signedWithMessageDigest);
		expected = true;
		assertTrue(actual);
		assertEquals(actual, expected);
		value = "Im a hacker and changed secured data";
		actual = DigitalSignaturesExtensions.verify(cert, "SHA-256", "RSA", value.getBytes(charset),
			signedWithMessageDigest);
		expected = false;
		assertFalse(actual);
		assertEquals(actual, expected);
	}

	/**
	 * Test chained encrypt and decrypt with
	 * {@link DigitalSignaturesExtensions#sign(PrivateKey, String, String, byte[])}
	 * {@link DigitalSignaturesExtensions#verify(PublicKey, String, String, byte[], byte[])}
	 *
	 * @throws Exception
	 *             is thrown if any security exception occured
	 */
	@Test
	public void testSignWithMessageDigest() throws Exception
	{
		String expected;
		File publickeyDerDir;
		File publickeyDerFile;
		File privatekeyDerFile;
		PrivateKey privateKey;
		PublicKey publicKey;

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "/der");
		publickeyDerFile = new File(publickeyDerDir, "public.der");
		privatekeyDerFile = new File(publickeyDerDir, "private.der");
		expected = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);

		byte[] signedWithMessageDigest = DigitalSignaturesExtensions.sign(privateKey, "SHA-256",
			"RSA", expected.getBytes());

		boolean verifed = DigitalSignaturesExtensions.verify(publicKey, "SHA-256", "RSA",
			expected.getBytes(), signedWithMessageDigest);
		assertTrue(verifed);
	}

}
