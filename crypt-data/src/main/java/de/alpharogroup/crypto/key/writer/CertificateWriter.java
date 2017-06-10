package de.alpharogroup.crypto.key.writer;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.apache.commons.codec.binary.Base64;

import lombok.NonNull;

/**
 * The class {@link CertificateWriter} is a utility class for write certificates
 * in files or streams.
 */
public class CertificateWriter {

	/**
	 * Write the given {@link X509Certificate} into the given {@link File} in
	 * the *.pem format.
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
	public static void write(final X509Certificate certificate, final @NonNull File file)
			throws IOException, CertificateEncodingException {
		write(certificate, new FileOutputStream(file));
	}

	/**
	 * Write the given {@link X509Certificate} into the given
	 * {@link OutputStream} in the *.pem format.
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
	public static void write(final X509Certificate certificate, final @NonNull OutputStream outputStream)
			throws IOException, CertificateEncodingException {
		final byte[] certificateBytes = certificate.getEncoded();
		outputStream.write("-----BEGIN CERTIFICATE-----\n".getBytes("US-ASCII"));
		outputStream.write(Base64.encodeBase64(certificateBytes, true));
		outputStream.write("-----END CERTIFICATE-----\n".getBytes("US-ASCII"));
		outputStream.close();
	}
}
