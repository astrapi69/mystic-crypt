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
package io.github.astrapi69.mystic.crypt.cli;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.EnumSet;
import java.util.HexFormat;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.key.writer.PrivateKeyWriter;
import io.github.astrapi69.crypt.data.key.writer.PublicKeyWriter;
import picocli.CommandLine.Help.Ansi;

/**
 * Small shared helpers for the CLI subcommands.
 */
final class CliSupport
{

	static final HexFormat HEX = HexFormat.of();

	/** Key algorithms that take a classical key size; everything else has a fixed parameter set. */
	private static final EnumSet<KeyPairGeneratorAlgorithm> SIZE_BASED = EnumSet.of(
		KeyPairGeneratorAlgorithm.RSA, KeyPairGeneratorAlgorithm.DSA,
		KeyPairGeneratorAlgorithm.DIFFIE_HELLMAN, KeyPairGeneratorAlgorithm.DH);

	private CliSupport()
	{
	}

	/**
	 * Parses a {@link KeyPairGeneratorAlgorithm} from a user string, accepting either dashes or
	 * underscores (e.g. {@code ML-KEM-768} or {@code ML_KEM_768}).
	 *
	 * @param value
	 *            the algorithm name
	 * @return the parsed algorithm
	 * @throws IllegalArgumentException
	 *             if the name is not a known algorithm
	 */
	static KeyPairGeneratorAlgorithm parseKeyPairAlgorithm(String value)
	{
		try
		{
			return KeyPairGeneratorAlgorithm.valueOf(value.trim().toUpperCase().replace('-', '_'));
		}
		catch (IllegalArgumentException exception)
		{
			throw new IllegalArgumentException("unknown key algorithm '" + value
				+ "'. Use one of the KeyPairGeneratorAlgorithm names, e.g. RSA, X25519, X448, "
				+ "ML_KEM_768, ML_DSA_65.");
		}
	}

	/** Whether the given key algorithm is initialized with a classical key size. */
	static boolean isSizeBased(KeyPairGeneratorAlgorithm algorithm)
	{
		return SIZE_BASED.contains(algorithm);
	}

	/**
	 * Resolves text input from either the {@code --text} value or, when {@code stdin} is set, all
	 * of standard input.
	 *
	 * @param text
	 *            the value of {@code --text} (may be {@code null})
	 * @param stdin
	 *            whether to read the text from standard input instead
	 * @return the resolved text
	 */
	static String resolveText(String text, boolean stdin)
	{
		if (stdin)
		{
			try
			{
				return new String(System.in.readAllBytes(), StandardCharsets.UTF_8);
			}
			catch (java.io.IOException exception)
			{
				throw new IllegalArgumentException(
					"could not read text from standard input: " + exception.getMessage(),
					exception);
			}
		}
		if (text == null)
		{
			throw new IllegalArgumentException("text is required: pass --text or --text-stdin");
		}
		return text;
	}

	/**
	 * Resolves a password from either the {@code --password} value or, when {@code stdin} is set,
	 * the first line read from standard input. Reading from stdin keeps the secret out of the
	 * process argument list.
	 *
	 * @param password
	 *            the value of {@code --password} (may be {@code null})
	 * @param stdin
	 *            whether to read the password from standard input instead
	 * @return the resolved password
	 * @throws IllegalArgumentException
	 *             if neither a password nor stdin was provided, or stdin was empty
	 */
	static String resolvePassword(String password, boolean stdin)
	{
		if (stdin)
		{
			try
			{
				BufferedReader reader = new BufferedReader(
					new InputStreamReader(System.in, StandardCharsets.UTF_8));
				String line = reader.readLine();
				if (line == null)
				{
					throw new IllegalArgumentException(
						"no password was provided on standard input");
				}
				return line;
			}
			catch (java.io.IOException exception)
			{
				throw new IllegalArgumentException(
					"could not read the password from standard input: " + exception.getMessage(),
					exception);
			}
		}
		if (password == null)
		{
			throw new IllegalArgumentException(
				"a password is required: pass --password or --password-stdin");
		}
		return password;
	}

	/** Renders an error line for a failed subcommand. */
	static String error(String message)
	{
		return Ansi.AUTO.string("@|red error:|@ " + message);
	}

	/**
	 * Writes a private key in PEM to the given file, or prints it to stdout when {@code out} is
	 * {@code null}. Uses the file-based PEM writer (the only exported one) via a temporary file for
	 * the stdout case.
	 *
	 * @param privateKey
	 *            the private key
	 * @param out
	 *            the target file, or {@code null} to print to stdout
	 * @throws IOException
	 *             if writing fails
	 */
	static void writePrivateKeyPem(PrivateKey privateKey, File out) throws IOException
	{
		if (out != null)
		{
			PrivateKeyWriter.writeInPemFormat(privateKey, out);
			return;
		}
		File temp = File.createTempFile("mystic-crypt-private", ".pem");
		try
		{
			PrivateKeyWriter.writeInPemFormat(privateKey, temp);
			System.out.print(Files.readString(temp.toPath(), StandardCharsets.UTF_8));
		}
		finally
		{
			Files.deleteIfExists(temp.toPath());
		}
	}

	/**
	 * Writes a public key in PEM to the given file, or prints it to stdout when {@code out} is
	 * {@code null}.
	 *
	 * @param publicKey
	 *            the public key
	 * @param out
	 *            the target file, or {@code null} to print to stdout
	 * @throws IOException
	 *             if writing fails
	 */
	static void writePublicKeyPem(PublicKey publicKey, File out) throws IOException
	{
		if (out != null)
		{
			PublicKeyWriter.writeInPemFormat(publicKey, out);
			return;
		}
		File temp = File.createTempFile("mystic-crypt-public", ".pem");
		try
		{
			PublicKeyWriter.writeInPemFormat(publicKey, temp);
			System.out.print(Files.readString(temp.toPath(), StandardCharsets.UTF_8));
		}
		finally
		{
			Files.deleteIfExists(temp.toPath());
		}
	}
}
