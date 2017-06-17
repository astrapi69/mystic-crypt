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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.commons.codec.binary.Base64;

import lombok.experimental.UtilityClass;

/**
 * The class {@link CertificateReader} is a utility class for reading certificates.
 */
@UtilityClass
public class CertificateReader
{

	/** The Constant BEGIN_CERTIFICATE_PREFIX. */
	public static final String BEGIN_CERTIFICATE_PREFIX = "-----BEGIN CERTIFICATE-----\n";

	/** The Constant END_CERTIFICATE_SUFFIX. */
	public static final String END_CERTIFICATE_SUFFIX = "-----END CERTIFICATE-----";

	/**
	 * Read pem certificate.
	 *
	 * @param file
	 *            the file
	 * @return the certificate
	 * @throws Exception
	 *             is thrown if if a security error occur
	 */
	public static X509Certificate readPemCertificate(final File file) throws Exception
	{
		final String privateKeyAsString = readPemFileAsBase64(file);
		final byte[] decoded = new Base64().decode(privateKeyAsString);
		return readCertificate(decoded);
	}

	/**
	 * Read the certificate from a pem file as base64 encoded {@link String} value.
	 *
	 * @param file
	 *            the file in pem format that contains the public key.
	 * @return the base64 encoded {@link String} value.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static String readPemFileAsBase64(final File file) throws IOException
	{
		final byte[] keyBytes = Files.readAllBytes(file.toPath());
		final String publicKeyAsBase64String = new String(keyBytes)
			.replace(BEGIN_CERTIFICATE_PREFIX, "").replace(END_CERTIFICATE_SUFFIX, "");
		return publicKeyAsBase64String;
	}

	/**
	 * Reads the given file in *.der format and tries to create a {@link X509Certificate} object.
	 *
	 * @param file
	 *            the file
	 * @return the {@link X509Certificate} object from the given byte array.
	 * @throws CertificateException
	 *             is thrown if no Provider supports a CertificateFactorySpi implementation for the
	 *             specified type.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static X509Certificate readCertificate(final File file)
		throws CertificateException, IOException
	{
		final byte[] decoded = Files.readAllBytes(file.toPath());
		return readCertificate(decoded);
	}

	/**
	 * Reads the given byte array and tries to create a {@link X509Certificate} object.
	 *
	 * @param decoded
	 *            the decoded
	 * @return the {@link X509Certificate} object from the given byte array.
	 * @throws CertificateException
	 *             is thrown if no Provider supports a CertificateFactorySpi implementation for the
	 *             specified type.
	 */
	public static X509Certificate readCertificate(final byte[] decoded) throws CertificateException
	{
		final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		final InputStream inputStream = new ByteArrayInputStream(decoded);
		final X509Certificate certificate = (X509Certificate)certificateFactory
			.generateCertificate(inputStream);
		return certificate;
	}

}
