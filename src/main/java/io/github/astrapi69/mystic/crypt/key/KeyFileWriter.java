/*
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
package io.github.astrapi69.mystic.crypt.key;

import java.io.IOException;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import io.github.astrapi69.crypt.data.key.PrivateKeyExtensions;

/**
 * Writes a key as PEM or DER, in the encoding that was actually asked for.
 * <p>
 * This was a workaround while {@code PrivateKeyWriter.write(..., KeyFormat.PKCS_8)} in crypt-data
 * wrote PKCS#1 under a PKCS#8 header. That is fixed at its source since crypt-data 12.1, so the
 * conversions are its again and what is left here is the shape the commands want: text and bytes
 * rather than a stream, and one place to ask for either encoding.
 * <p>
 * The workaround had carried a smaller version of the same fault - it labelled the traditional form
 * of anything but RSA {@code PRIVATE KEY}, which means PKCS#8, over content with the wrapper
 * stripped. crypt-data picks the header that belongs to the algorithm, so that goes with it.
 */
public final class KeyFileWriter
{

	/** The PEM label of a PKCS#8 private key, which carries its algorithm inside the structure. */
	public static final String PKCS8_LABEL = "PRIVATE KEY";

	/** The PEM label of a traditional RSA private key. */
	public static final String PKCS1_RSA_LABEL = "RSA PRIVATE KEY";

	/** The PEM label of a public key. */
	public static final String PUBLIC_LABEL = "PUBLIC KEY";

	private KeyFileWriter()
	{
	}

	/**
	 * The PKCS#8 encoding of the given private key, which is what {@code getEncoded} already
	 * returns.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the DER bytes in PKCS#8
	 */
	public static byte[] toPkcs8(final PrivateKey privateKey)
	{
		return privateKey.getEncoded();
	}

	/**
	 * The PKCS#1 encoding of the given private key, the inner structure with the PKCS#8 wrapper
	 * removed.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the DER bytes in PKCS#1
	 * @throws IOException
	 *             if the key cannot be re-encoded
	 */
	public static byte[] toPkcs1(final PrivateKey privateKey) throws IOException
	{
		return PrivateKeyExtensions.toPKCS1Format(privateKey);
	}

	/**
	 * Renders a private key as PEM in the requested encoding.
	 *
	 * @param privateKey
	 *            the private key
	 * @param pkcs1
	 *            true for the traditional PKCS#1 form, false for PKCS#8
	 * @return the PEM text
	 * @throws IOException
	 *             if the key cannot be re-encoded
	 */
	public static String toPem(final PrivateKey privateKey, final boolean pkcs1) throws IOException
	{
		return pkcs1
			? PrivateKeyExtensions.toPemFormat(privateKey)
			: PrivateKeyExtensions.toPkcs8PemFormat(privateKey);
	}

	/**
	 * Renders a public key as PEM.
	 *
	 * @param publicKey
	 *            the public key
	 * @return the PEM text
	 * @throws IOException
	 *             if the key cannot be written
	 */
	public static String toPem(final PublicKey publicKey) throws IOException
	{
		return toPem(PUBLIC_LABEL, publicKey.getEncoded());
	}

	/**
	 * Renders the given DER bytes as PEM under the given label.
	 *
	 * @param label
	 *            the PEM label, e.g. {@code PRIVATE KEY}
	 * @param der
	 *            the DER bytes
	 * @return the PEM text
	 * @throws IOException
	 *             if the text cannot be written
	 */
	public static String toPem(final String label, final byte[] der) throws IOException
	{
		final StringWriter text = new StringWriter();
		try (PemWriter writer = new PemWriter(text))
		{
			writer.writeObject(new PemObject(label, der));
		}
		return text.toString();
	}

}
