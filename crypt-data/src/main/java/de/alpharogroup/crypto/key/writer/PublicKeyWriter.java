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
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import lombok.NonNull;
import lombok.experimental.UtilityClass;

/**
 * The class {@link PublicKeyWriter} is a utility class for write public keys in files or streams.
 */
@UtilityClass
public class PublicKeyWriter
{

	/**
	 * Write the given {@link PublicKey} into the given {@link File}.
	 *
	 * @param publicKey
	 *            the public key
	 * @param file
	 *            the file to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void write(final PublicKey publicKey, final @NonNull File file) throws IOException
	{
		write(publicKey, new FileOutputStream(file));
	}

	/**
	 * Write the given {@link PublicKey} into the given {@link OutputStream}.
	 *
	 * @param publicKey
	 *            the public key
	 * @param outputStream
	 *            the output stream to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void write(final PublicKey publicKey, final @NonNull OutputStream outputStream)
		throws IOException
	{
		final byte[] publicKeyBytes = publicKey.getEncoded();
		final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
		outputStream.write(keySpec.getEncoded());
		outputStream.close();
	}

	/**
	 * Write the given {@link PublicKey} into the given {@link File}.
	 *
	 * @param publicKey
	 *            the public key
	 * @param file
	 *            the file to write in
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void writeInPemFormat(final PublicKey publicKey, final @NonNull File file)
		throws IOException
	{
		KeyWriter.writeInPemFormat(publicKey, file);
	}

}
