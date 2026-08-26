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

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * Writes a key as PEM or DER, in the encoding that was actually asked for.
 * <p>
 * This exists because {@code PrivateKeyWriter.write(..., KeyFormat.PKCS_8)} in crypt-data does not
 * write PKCS#8: it routes through {@code PrivateKeyExtensions.toPemFormat}, which calls
 * {@code toPKCS1Format} for every key type and so strips the PKCS#8 wrapper before armouring the
 * result. Asking for PKCS#8 there yields PKCS#1 under an RSA PRIVATE KEY header. Until that is
 * fixed at its source, the commands that let a user choose the encoding use this instead, so what
 * the option says is what lands in the file.
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
		final PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
		final ASN1Primitive inner = privateKeyInfo.parsePrivateKey().toASN1Primitive();
		return inner.getEncoded();
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
			? toPem(labelFor(privateKey), toPkcs1(privateKey))
			: toPem(PKCS8_LABEL, toPkcs8(privateKey));
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

	/**
	 * The PEM label a traditional private key of this algorithm is written under. Only RSA has a
	 * widely used traditional label of its own; anything else keeps the PKCS#8 label, because there
	 * is no traditional form for it to be mistaken for.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the PEM label
	 */
	private static String labelFor(final PrivateKey privateKey)
	{
		return "RSA".equals(privateKey.getAlgorithm()) ? PKCS1_RSA_LABEL : PKCS8_LABEL;
	}
}
