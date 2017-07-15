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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.apache.commons.codec.binary.Base64;

import de.alpharogroup.crypto.key.KeyFileFormat;
import de.alpharogroup.crypto.key.reader.CertificateReader;
import lombok.NonNull;

/**
 * The class {@link CertificateWriter} is a utility class for write certificates in files or streams
 * in several file formats.
 */
public class CertificateWriter
{

	/**
	 * Write the given {@link X509Certificate} into the given {@link File} in the given
	 * {@link KeyFileFormat} format.
	 *
	 * @param certificate
	 *            the certificate
	 * @param file
	 *            the file to write in
	 * @param fileFormat
	 *            the file format to write
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	public static void write(final X509Certificate certificate, final @NonNull File file,
		KeyFileFormat fileFormat) throws IOException, CertificateEncodingException
	{
		write(certificate, new FileOutputStream(file), fileFormat);
	}

	/**
	 * Write the given {@link X509Certificate} into the given {@link OutputStream} in the given
	 * {@link KeyFileFormat} format.
	 *
	 * @param certificate
	 *            the certificate
	 * @param outputStream
	 *            the output stream
	 * @param fileFormat
	 *            the file format to write
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	public static void write(final X509Certificate certificate,
		final @NonNull OutputStream outputStream, KeyFileFormat fileFormat)
		throws IOException, CertificateEncodingException
	{
		final byte[] certificateBytes = certificate.getEncoded();
		switch (fileFormat)
		{
			case DER :
				outputStream.write(certificateBytes);
				break;
			case PEM :
				outputStream.write(
					CertificateReader.BEGIN_CERTIFICATE_PREFIX.getBytes(StandardCharsets.US_ASCII));
				outputStream.write(Base64.encodeBase64(certificateBytes, true));
				outputStream.write(
					CertificateReader.END_CERTIFICATE_SUFFIX.getBytes(StandardCharsets.US_ASCII));
				break;
			default :
				outputStream.write(certificateBytes);
				break;
		}
		outputStream.close();
	}

	/**
	 * Write the given {@link X509Certificate} into the given {@link File} in the *.der format.
	 *
	 * @param certificate
	 *            the certificate
	 * @param file
	 *            the file to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	public static void writeInDerFormat(final X509Certificate certificate, final @NonNull File file)
		throws IOException, CertificateEncodingException
	{
		writeInDerFormat(certificate, new FileOutputStream(file));
	}

	/**
	 * Write the given {@link X509Certificate} into the given {@link OutputStream} in the *.pem
	 * format.
	 *
	 * @param certificate
	 *            the certificate
	 * @param outputStream
	 *            the output stream to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	public static void writeInDerFormat(final X509Certificate certificate,
		final @NonNull OutputStream outputStream) throws IOException, CertificateEncodingException
	{
		write(certificate, outputStream, KeyFileFormat.DER);
	}

	/**
	 * Write the given {@link X509Certificate} into the given {@link File} in the *.pem format.
	 *
	 * @param certificate
	 *            the certificate
	 * @param file
	 *            the file to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	public static void writeInPemFormat(final X509Certificate certificate, final @NonNull File file)
		throws IOException, CertificateEncodingException
	{
		writeInPemFormat(certificate, new FileOutputStream(file));
	}

	/**
	 * Write the given {@link X509Certificate} into the given {@link OutputStream} in the *.pem
	 * format.
	 *
	 * @param certificate
	 *            the certificate
	 * @param outputStream
	 *            the output stream to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws CertificateEncodingException
	 *             is thrown if an encoding error occurs.
	 */
	public static void writeInPemFormat(final X509Certificate certificate,
		final @NonNull OutputStream outputStream) throws IOException, CertificateEncodingException
	{
		write(certificate, outputStream, KeyFileFormat.PEM);
	}

}
