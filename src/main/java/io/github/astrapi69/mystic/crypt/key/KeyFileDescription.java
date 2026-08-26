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

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;

/**
 * What a key or certificate file turns out to be, so a conversion can say what it found before it
 * changes anything.
 *
 * @param encoding
 *            whether the file is PEM or DER
 * @param content
 *            what the file holds
 * @param algorithm
 *            the key algorithm, as the object identifier the file carries
 */
public record KeyFileDescription(Encoding encoding, Content content, String algorithm) {

	/** How the bytes are wrapped. */
	public enum Encoding
	{
		/** Base64 between BEGIN and END lines. */
		PEM,
		/** Raw DER bytes. */
		DER
	}

	/** What the file holds. */
	public enum Content
	{
		/** A private key in the PKCS#8 wrapper. */
		PRIVATE_KEY_PKCS8,
		/** A private key in the traditional form, without the PKCS#8 wrapper. */
		PRIVATE_KEY_PKCS1,
		/** A public key. */
		PUBLIC_KEY,
		/** An X.509 certificate. */
		CERTIFICATE
	}

	/**
	 * Examines the given file.
	 *
	 * @param file
	 *            the file to examine
	 * @return what it holds
	 * @throws IOException
	 *             if the file cannot be read
	 * @throws IllegalArgumentException
	 *             if the file is neither a key nor a certificate this tool recognises
	 */
	public static KeyFileDescription of(final File file) throws IOException
	{
		return KeyFileReader.isPem(file) ? describePem(file) : describeDer(file);
	}

	/**
	 * A sentence naming what was found, for a user who asked what a file is.
	 *
	 * @return the description as one line
	 */
	public String describe()
	{
		final String what = switch (content)
		{
			case PRIVATE_KEY_PKCS8 -> "a private key in PKCS#8";
			case PRIVATE_KEY_PKCS1 -> "a private key in PKCS#1, the traditional form";
			case PUBLIC_KEY -> "a public key";
			case CERTIFICATE -> "an X.509 certificate";
		};
		return what + ", " + encoding + " encoded, algorithm " + algorithm;
	}

	private static KeyFileDescription describePem(final File file) throws IOException
	{
		final Object pemObject = readPem(file);
		if (pemObject instanceof PEMKeyPair pemKeyPair)
		{
			return new KeyFileDescription(Encoding.PEM, Content.PRIVATE_KEY_PKCS1,
				algorithmOf(pemKeyPair.getPrivateKeyInfo()));
		}
		if (pemObject instanceof PrivateKeyInfo privateKeyInfo)
		{
			return new KeyFileDescription(Encoding.PEM, Content.PRIVATE_KEY_PKCS8,
				algorithmOf(privateKeyInfo));
		}
		if (pemObject instanceof SubjectPublicKeyInfo publicKeyInfo)
		{
			return new KeyFileDescription(Encoding.PEM, Content.PUBLIC_KEY,
				publicKeyInfo.getAlgorithm().getAlgorithm().getId());
		}
		if (pemObject instanceof X509CertificateHolder certificate)
		{
			return new KeyFileDescription(Encoding.PEM, Content.CERTIFICATE,
				certificate.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId());
		}
		throw new IllegalArgumentException("'" + file + "' holds "
			+ (pemObject == null ? "no PEM object" : "a " + pemObject.getClass().getSimpleName())
			+ ", which is not a key or a certificate this tool converts");
	}

	private static KeyFileDescription describeDer(final File file) throws IOException
	{
		final byte[] der = Files.readAllBytes(file.toPath());
		try
		{
			return new KeyFileDescription(Encoding.DER, Content.PRIVATE_KEY_PKCS8,
				algorithmOf(PrivateKeyInfo.getInstance(der)));
		}
		catch (final RuntimeException notPkcs8)
		{
			// fall through to the next shape
		}
		try
		{
			final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(der);
			return new KeyFileDescription(Encoding.DER, Content.PUBLIC_KEY,
				publicKeyInfo.getAlgorithm().getAlgorithm().getId());
		}
		catch (final RuntimeException notAPublicKey)
		{
			// fall through to the next shape
		}
		try
		{
			final X509CertificateHolder certificate = new X509CertificateHolder(der);
			return new KeyFileDescription(Encoding.DER, Content.CERTIFICATE,
				certificate.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId());
		}
		catch (final RuntimeException | IOException notACertificate)
		{
			throw new IllegalArgumentException("'" + file
				+ "' is not a DER private key, public key or X.509 certificate this tool converts");
		}
	}

	private static Object readPem(final File file) throws IOException
	{
		try (PEMParser parser = new PEMParser(new FileReader(file, StandardCharsets.UTF_8)))
		{
			try
			{
				return parser.readObject();
			}
			catch (final IOException malformed)
			{
				throw new IllegalArgumentException(
					"could not read a PEM object from '" + file + "': " + malformed.getMessage(),
					malformed);
			}
		}
	}

	private static String algorithmOf(final PrivateKeyInfo privateKeyInfo)
	{
		return privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm().getId();
	}
}
