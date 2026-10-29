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
package io.github.astrapi69.mystic.crypt.gnupg;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.System.Logger.Level;
import java.math.BigInteger;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.ECPublicBCPGKey;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.gpg.PGPSecretKeyParser;
import org.bouncycastle.gpg.SExpression;

/**
 * Which keys have their secret part in a GnuPG home's {@code private-keys-v1.d}, told without
 * decrypting anything.
 * <p>
 * gpg names each file there by the key's keygrip, which Bouncy Castle's {@code KeyGripCalculator}
 * does not compute the way gpg does: it hashes the RSA modulus without the leading zero byte gpg
 * hashes, and it refuses elliptic curve keys. But every file also carries the key's public part in
 * the clear - the modulus {@code n} of an RSA key, the point {@code q} of an elliptic curve key -
 * and that is matched against the public keys of the keyring instead.
 */
final class SecretKeyFiles
{

	private static final System.Logger LOGGER = System.getLogger(SecretKeyFiles.class.getName());

	/** How deep Bouncy Castle may nest while parsing one file; gpg's files are a few levels deep */
	private static final int MAXIMUM_DEPTH = 10;

	/** A key file is a few kilobytes; anything far beyond is not one, and is not parsed */
	private static final long MAXIMUM_FILE_SIZE = 64 * 1024;

	/** The two kinds of file that hold a secret part in this home, protected or not */
	private static final String[] SECRET_KEY_LABELS = { "protected-private-key", "private-key" };

	private final Set<BigInteger> publicParts;

	private final boolean complete;

	private SecretKeyFiles(final Set<BigInteger> publicParts, final boolean complete)
	{
		this.publicParts = publicParts;
		this.complete = complete;
	}

	/**
	 * Reads the public part of every key file in the directory
	 *
	 * @param directory
	 *            the home's {@code private-keys-v1.d}, which need not exist
	 * @return what the directory holds
	 */
	static SecretKeyFiles in(final Path directory) throws IOException
	{
		Set<BigInteger> publicParts = new HashSet<>();
		boolean complete = true;
		if (!Files.isDirectory(directory))
		{
			return new SecretKeyFiles(publicParts, complete);
		}
		try (DirectoryStream<Path> files = Files.newDirectoryStream(directory, "*.key"))
		{
			for (Path file : files)
			{
				BigInteger publicPart = publicPartOf(file);
				if (publicPart == null)
				{
					complete = false;
				}
				else
				{
					publicParts.add(publicPart);
				}
			}
		}
		return new SecretKeyFiles(publicParts, complete);
	}

	/**
	 * Where the secret part of the key with the given public key is
	 *
	 * @param publicKey
	 *            the key's public part as the keyring holds it
	 * @return here, offline, or unknown when the algorithm is not matched or a file was unreadable
	 */
	SecretPart of(final BCPGKey publicKey)
	{
		BigInteger publicPart = publicPartOf(publicKey);
		if (publicPart != null && publicParts.contains(publicPart))
		{
			return SecretPart.HERE;
		}
		return publicPart != null && complete ? SecretPart.OFFLINE : SecretPart.UNKNOWN;
	}

	private static BigInteger publicPartOf(final BCPGKey publicKey)
	{
		if (publicKey instanceof RSAPublicBCPGKey rsa)
		{
			return rsa.getModulus();
		}
		if (publicKey instanceof ECPublicBCPGKey ellipticCurve)
		{
			return ellipticCurve.getEncodedPoint();
		}
		return null;
	}

	/**
	 * The public part one key file carries, null when the file cannot be read, is of a kind that
	 * holds no secret part here (a key on a smartcard), or of an algorithm not matched
	 */
	private static BigInteger publicPartOf(final Path file)
	{
		try
		{
			if (Files.size(file) > MAXIMUM_FILE_SIZE)
			{
				LOGGER.log(Level.WARNING, () -> "not read, larger than a key file: " + file);
				return null;
			}
			SExpression key = parse(file);
			if (!isSecretKey(key))
			{
				LOGGER.log(Level.INFO, () -> "holds no secret part of its own: " + file);
				return null;
			}
			byte[] publicPart = valueOf(key, "n");
			return new BigInteger(1, publicPart != null ? publicPart : requiredValueOf(key, "q"));
		}
		catch (IOException | IllegalArgumentException | IllegalStateException exception)
		{
			LOGGER.log(Level.WARNING, "could not read the key file " + file, exception);
			return null;
		}
	}

	private static SExpression parse(final Path file) throws IOException
	{
		try (InputStream in = new BufferedInputStream(Files.newInputStream(file)))
		{
			return PGPSecretKeyParser.parse(in, MAXIMUM_DEPTH).getKeyExpression();
		}
	}

	private static boolean isSecretKey(final SExpression key)
	{
		for (String label : SECRET_KEY_LABELS)
		{
			if (isLabelled(key, label))
			{
				return true;
			}
		}
		return false;
	}

	private static byte[] requiredValueOf(final SExpression key, final String label)
	{
		byte[] value = valueOf(key, label);
		if (value == null)
		{
			throw new IllegalArgumentException("no public part n or q in the key");
		}
		return value;
	}

	/**
	 * Whether the expression starts with the given label. Bouncy Castle's own check casts the first
	 * value to bytes, which throws for an expression that starts with another expression, as gpg's
	 * protected keys contain
	 */
	private static boolean isLabelled(final SExpression expression, final String label)
	{
		return !expression.getValues().isEmpty() && expression.getValue(0) instanceof String
			&& expression.hasLabel(label);
	}

	/** The bytes of the first expression with the given label, searched depth first */
	private static byte[] valueOf(final SExpression expression, final String label)
	{
		if (isLabelled(expression, label) && expression.getValues().size() > 1
			&& expression.getValue(1)instanceof byte[] bytes)
		{
			return bytes;
		}
		for (Object value : expression.getValues())
		{
			if (value instanceof SExpression child)
			{
				byte[] found = valueOf(child, label);
				if (found != null)
				{
					return found;
				}
			}
		}
		return null;
	}
}
