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

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;

/**
 * Shared plumbing of the {@code encrypt} and {@code decrypt} commands: both resolve the same kind
 * of input (a file or a piece of text), the same passphrase sources and the same output target, and
 * differ only in the transformation between them.
 */
final class PassphraseCryptSupport
{

	private PassphraseCryptSupport()
	{
	}

	/**
	 * Resolves the passphrase from the option value or from standard input.
	 * <p>
	 * Reading it from standard input keeps it out of the process argument list, which is why the
	 * plain option carries a warning in its own help text rather than being removed: scripts that
	 * cannot pipe still need a way in.
	 *
	 * @param passphrase
	 *            the value of {@code --passphrase}, or null
	 * @param stdin
	 *            whether to read the passphrase from standard input
	 * @return the passphrase, to be zeroed by the caller
	 * @throws IllegalArgumentException
	 *             if neither source was given
	 */
	static char[] resolvePassphrase(final String passphrase, final boolean stdin)
	{
		if (stdin)
		{
			return CliSupport.resolvePassword(null, true).toCharArray();
		}
		if (passphrase == null)
		{
			throw new IllegalArgumentException(
				"a passphrase is required: pass --passphrase or --passphrase-stdin");
		}
		return passphrase.toCharArray();
	}

	/**
	 * Rejects the one option combination that cannot work: two options that both want to consume
	 * standard input. Without this the second read silently returns nothing and the user is left
	 * guessing why the passphrase was empty.
	 *
	 * @param textStdin
	 *            whether the text is to be read from standard input
	 * @param passphraseStdin
	 *            whether the passphrase is to be read from standard input
	 * @throws IllegalArgumentException
	 *             if both are set
	 */
	static void requireOnlyOneStandardInputReader(final boolean textStdin,
		final boolean passphraseStdin)
	{
		if (textStdin && passphraseStdin)
		{
			throw new IllegalArgumentException(
				"--text-stdin and --passphrase-stdin both read standard input, so they cannot be "
					+ "combined: pass the passphrase with --passphrase, or the text with --text");
		}
	}

	/**
	 * Reads the bytes to process, either from the given file or from the given text.
	 *
	 * @param in
	 *            the input file, or null when text is used
	 * @param text
	 *            the value of {@code --text}, or null when a file is used
	 * @param textStdin
	 *            whether the text is to be read from standard input
	 * @return the bytes to process
	 * @throws IOException
	 *             if the file cannot be read
	 */
	static byte[] readInput(final File in, final String text, final boolean textStdin)
		throws IOException
	{
		if (in != null)
		{
			return CliSupport.readData(in);
		}
		return CliSupport.resolveText(text, textStdin).getBytes(StandardCharsets.UTF_8);
	}

	/**
	 * Writes the result to the given file, or returns it for printing when no file was given.
	 *
	 * @param out
	 *            the target file, or null to print
	 * @param result
	 *            the bytes to write
	 * @param printable
	 *            how to render the bytes when they are printed rather than written
	 * @return the line to print, or null when the result was written to the file
	 * @throws IOException
	 *             if the file cannot be written
	 */
	static String writeOutput(final File out, final byte[] result, final Printable printable)
		throws IOException
	{
		if (out != null)
		{
			Files.write(out.toPath(), result);
			return null;
		}
		return printable.render(result);
	}

	/** Renders result bytes for printing to standard output. */
	@FunctionalInterface
	interface Printable
	{
		/**
		 * Renders the given bytes as a line of text.
		 *
		 * @param result
		 *            the bytes to render
		 * @return the text to print
		 */
		String render(byte[] result);
	}

	/** Renders encrypted bytes as base64, the only printable form of arbitrary bytes. */
	static String asBase64(final byte[] result)
	{
		return Base64.getEncoder().encodeToString(result);
	}

	/** Renders decrypted bytes as the UTF-8 text they were before encryption. */
	static String asText(final byte[] result)
	{
		return new String(result, StandardCharsets.UTF_8);
	}
}
