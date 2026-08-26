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
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Reads a private or public key from a file that may be PEM or DER, always through Bouncy Castle.
 * <p>
 * The provider is not an incidental choice. An elliptic-curve key generated on a <em>named
 * curve</em> by Bouncy Castle is rejected by the JDK's own SunEC provider when it is used to sign
 * ("Curve not supported"), and - worse - verification with such a key returns {@code false} instead
 * of throwing, so a perfectly good signature reads as an invalid one and nothing says why. Decoding
 * the key with the same provider that will sign and verify with it keeps that mismatch from
 * arising, which is why this exists next to the readers in crypt-data: those call
 * {@code KeyFactory.getInstance(algorithm)} without naming a provider, and for {@code EC} the JDK's
 * own provider wins that lookup.
 */
public final class KeyFileReader
{

	private KeyFileReader()
	{
	}

	/**
	 * Reads a private key from a PEM or DER file.
	 *
	 * @param file
	 *            the key file
	 * @param algorithm
	 *            the key algorithm, e.g. {@code RSA}, {@code EC} or {@code DSA}
	 * @return the private key
	 * @throws IOException
	 *             if the file cannot be read
	 * @throws IllegalArgumentException
	 *             if the file holds no private key this provider can decode
	 */
	public static PrivateKey readPrivateKey(final File file, final String algorithm)
		throws IOException
	{
		SecurityProviderSupport.ensureBouncyCastle();
		if (isPem(file))
		{
			return privateKeyFromPem(file);
		}
		try
		{
			return keyFactory(algorithm)
				.generatePrivate(new PKCS8EncodedKeySpec(Files.readAllBytes(file.toPath())));
		}
		catch (final Exception notADerPrivateKey)
		{
			throw new IllegalArgumentException("could not read a " + algorithm
				+ " private key from '" + file + "': " + notADerPrivateKey.getMessage(),
				notADerPrivateKey);
		}
	}

	/**
	 * Reads a public key from a PEM or DER file.
	 *
	 * @param file
	 *            the key file
	 * @param algorithm
	 *            the key algorithm, e.g. {@code RSA}, {@code EC} or {@code DSA}
	 * @return the public key
	 * @throws IOException
	 *             if the file cannot be read
	 * @throws IllegalArgumentException
	 *             if the file holds no public key this provider can decode
	 */
	public static PublicKey readPublicKey(final File file, final String algorithm)
		throws IOException
	{
		SecurityProviderSupport.ensureBouncyCastle();
		if (isPem(file))
		{
			return publicKeyFromPem(file);
		}
		try
		{
			return keyFactory(algorithm)
				.generatePublic(new X509EncodedKeySpec(Files.readAllBytes(file.toPath())));
		}
		catch (final Exception notADerPublicKey)
		{
			throw new IllegalArgumentException("could not read a " + algorithm
				+ " public key from '" + file + "': " + notADerPublicKey.getMessage(),
				notADerPublicKey);
		}
	}

	/**
	 * Whether the given file is PEM rather than DER, decided by the armour a PEM file carries.
	 *
	 * @param file
	 *            the file to look at
	 * @return true if the file is PEM
	 * @throws IOException
	 *             if the file cannot be read
	 */
	public static boolean isPem(final File file) throws IOException
	{
		final byte[] head = Files.readAllBytes(file.toPath());
		final int lookAhead = Math.min(head.length, 64);
		return new String(head, 0, lookAhead, java.nio.charset.StandardCharsets.US_ASCII)
			.contains("-----BEGIN");
	}

	private static PrivateKey privateKeyFromPem(final File file) throws IOException
	{
		final Object pemObject = firstPemObject(file);
		final JcaPEMKeyConverter converter = converter();
		try
		{
			if (pemObject instanceof PEMKeyPair pemKeyPair)
			{
				return converter.getKeyPair(pemKeyPair).getPrivate();
			}
			if (pemObject instanceof PrivateKeyInfo privateKeyInfo)
			{
				return converter.getPrivateKey(privateKeyInfo);
			}
		}
		catch (final Exception cannotConvert)
		{
			throw new IllegalArgumentException(
				"could not read a private key from '" + file + "': " + cannotConvert.getMessage(),
				cannotConvert);
		}
		throw new IllegalArgumentException(
			"'" + file + "' holds " + describe(pemObject) + ", not a private key");
	}

	private static PublicKey publicKeyFromPem(final File file) throws IOException
	{
		final Object pemObject = firstPemObject(file);
		final JcaPEMKeyConverter converter = converter();
		try
		{
			if (pemObject instanceof SubjectPublicKeyInfo publicKeyInfo)
			{
				return converter.getPublicKey(publicKeyInfo);
			}
			if (pemObject instanceof PEMKeyPair pemKeyPair)
			{
				// a PEM holding a whole key pair also answers "what is the public half"
				return converter.getKeyPair(pemKeyPair).getPublic();
			}
		}
		catch (final Exception cannotConvert)
		{
			throw new IllegalArgumentException(
				"could not read a public key from '" + file + "': " + cannotConvert.getMessage(),
				cannotConvert);
		}
		throw new IllegalArgumentException(
			"'" + file + "' holds " + describe(pemObject) + ", not a public key");
	}

	/**
	 * Reads the first PEM object out of the file.
	 * <p>
	 * A body that is not valid for the armour around it makes Bouncy Castle throw out of
	 * {@code readObject} itself, before there is any object to look at. That is still "this file
	 * does not hold the key you asked for", so it is reported the same way rather than escaping as
	 * an IOException that reads like the file could not be opened. Only the opening itself keeps
	 * that meaning.
	 */
	private static Object firstPemObject(final File file) throws IOException
	{
		try (PEMParser parser = new PEMParser(new FileReader(file)))
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

	private static String describe(final Object pemObject)
	{
		return pemObject == null ? "no PEM object" : "a " + pemObject.getClass().getSimpleName();
	}

	private static JcaPEMKeyConverter converter()
	{
		return new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
	}

	private static KeyFactory keyFactory(final String algorithm) throws Exception
	{
		return KeyFactory.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
	}
}
