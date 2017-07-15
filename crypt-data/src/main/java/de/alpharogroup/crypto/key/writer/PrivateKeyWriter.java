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
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import de.alpharogroup.crypto.key.KeyFileFormat;
import de.alpharogroup.crypto.key.KeyFormat;
import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.file.write.WriteFileExtensions;
import lombok.NonNull;
import lombok.experimental.UtilityClass;

/**
 * The class {@link PrivateKeyWriter} is a utility class for write public keys in files or streams.
 */
@UtilityClass
public class PrivateKeyWriter
{

	/**
	 * Write the given {@link PrivateKey} into the given {@link File} in the *.der format.
	 *
	 * @param privateKey
	 *            the private key
	 * @param file
	 *            the file to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void write(final PrivateKey privateKey, final @NonNull File file)
		throws IOException
	{
		write(privateKey, new FileOutputStream(file));
	}

	/**
	 * Write the given {@link PrivateKey} into the given {@link OutputStream} in the *.der format.
	 *
	 * @param privateKey
	 *            the private key
	 * @param outputStream
	 *            the output stream to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void write(final PrivateKey privateKey, final @NonNull OutputStream outputStream)
		throws IOException
	{
		final byte[] privateKeyBytes = privateKey.getEncoded();
		final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		outputStream.write(keySpec.getEncoded());
		outputStream.close();
	}

	/**
	 * Write the given {@link PrivateKey} into the given {@link File}.
	 *
	 * @param privateKey
	 *            the private key
	 * @param file
	 *            the file to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void writeInPemFormat(final PrivateKey privateKey, final @NonNull File file)
		throws IOException
	{
		StringWriter stringWriter = new StringWriter();
		JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
		pemWriter.writeObject(privateKey);
		pemWriter.close();
		String pemFormat = stringWriter.toString();
		pemFormat = pemFormat.replaceAll("\\r\\n", "\\\n");
		WriteFileExtensions.string2File(file, pemFormat);
	}

	/**
	 * Write the given {@link PrivateKey} into the given {@link OutputStream} in the given formats.
	 *
	 * @param privateKey
	 *            the private key
	 * @param outputStream
	 *            the output stream
	 * @param fileFormat
	 *            the file format
	 * @param keyFormat
	 *            the private key format
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void write(final PrivateKey privateKey, final @NonNull OutputStream outputStream,
		KeyFileFormat fileFormat, KeyFormat keyFormat) throws IOException
	{
		final byte[] privateKeyBytes = privateKey.getEncoded();
		switch (fileFormat)
		{
			case DER :
			case PEM :
				if (keyFormat != null)
				{
					if (keyFormat.equals(KeyFormat.PKCS_8))
					{
						outputStream.write(PrivateKeyReader.BEGIN_PRIVATE_KEY_PREFIX
							.getBytes(StandardCharsets.US_ASCII));
						outputStream.write(Base64.encodeBase64(privateKeyBytes, true));
						outputStream.write(PrivateKeyReader.END_PRIVATE_KEY_SUFFIX
							.getBytes(StandardCharsets.US_ASCII));
						break;
					}
					else if (keyFormat.equals(KeyFormat.PKCS_1))
					{
						outputStream.write(PrivateKeyReader.BEGIN_RSA_PRIVATE_KEY_PREFIX
							.getBytes(StandardCharsets.US_ASCII));
						outputStream.write(Base64.encodeBase64(privateKeyBytes, true));
						outputStream.write(PrivateKeyReader.END_RSA_PRIVATE_KEY_SUFFIX
							.getBytes(StandardCharsets.US_ASCII));
						break;
					}
				}
			default : // DER is default
				final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
				outputStream.write(keySpec.getEncoded());
				break;
		}
		outputStream.close();
	}

}
