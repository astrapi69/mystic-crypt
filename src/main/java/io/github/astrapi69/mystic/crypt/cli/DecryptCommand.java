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
import java.util.Base64;
import java.util.concurrent.Callable;

import io.github.astrapi69.mystic.crypt.pw.PassphraseCryptor;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Decrypts what {@link EncryptCommand} produced.
 * <p>
 * A wrong passphrase and altered data are the negative answer to "can this be opened with this
 * passphrase", not a failure of the tool, so they exit with 1; an input that is not of this format
 * at all, or a file that cannot be read, exits with 2.
 */
@Command(name = "decrypt", mixinStandardHelpOptions = true, //
	description = "Decrypt a file or a text encrypted by 'encrypt'. Exit code 0 = decrypted, "
		+ "1 = wrong passphrase or altered data, 2 = error.")
public class DecryptCommand implements Callable<Integer>
{

	/**
	 * Instantiates a new {@link DecryptCommand}.
	 * <p>
	 * Declared explicitly, and public, because picocli builds this subcommand reflectively through
	 * its default factory when {@link MysticCryptCli} dispatches to it; the class must therefore
	 * keep an accessible no-argument constructor.
	 */
	public DecryptCommand()
	{
	}

	@Option(names = { "-i",
			"--in" }, description = "The file to decrypt, or '-' for standard input.")
	File in;

	@Option(names = { "-o",
			"--out" }, description = "The file to write. Without it the result is printed as text.")
	File out;

	@Option(names = { "-t",
			"--text" }, description = "The base64 text to decrypt instead of a file.")
	String text;

	@Option(names = "--text-stdin", description = "Read the base64 text to decrypt from standard input.")
	boolean textStdin;

	@Option(names = { "-p",
			"--passphrase" }, description = "The passphrase. Prefer --passphrase-stdin to keep it out of the process arguments.")
	String passphrase;

	@Option(names = "--passphrase-stdin", description = "Read the passphrase from the first line of standard input.")
	boolean passphraseStdin;

	@Override
	public Integer call()
	{
		CliSupport.refuseDashAsPath(out, "--out", CliSupport.LEAVE_IT_OUT);
		try
		{
			PassphraseCryptSupport.requireOnlyOneStandardInputReader(textStdin, passphraseStdin);
			byte[] encrypted = readEncrypted();
			char[] resolvedPassphrase = PassphraseCryptSupport.resolvePassphrase(passphrase,
				passphraseStdin);
			byte[] decrypted = PassphraseCryptor.decrypt(resolvedPassphrase, encrypted);
			String printed = PassphraseCryptSupport.writeOutput(out, decrypted,
				PassphraseCryptSupport::asText);
			if (printed == null)
			{
				System.out.println("decrypted " + decrypted.length + " bytes to " + out.getPath());
			}
			else
			{
				System.out.println(printed);
			}
			return 0;
		}
		catch (SecurityException wrongPassphraseOrAltered)
		{
			System.err.println(CliSupport.error(wrongPassphraseOrAltered.getMessage()));
			return 1;
		}
		catch (Exception exception)
		{
			System.err.println(CliSupport.error(exception.getMessage()));
			return 2;
		}
	}

	/**
	 * Reads the encrypted bytes. A file holds them raw, while the {@code --text} form carries the
	 * base64 that {@code encrypt} printed.
	 *
	 * @return the encrypted bytes
	 * @throws java.io.IOException
	 *             if the input file cannot be read
	 */
	private byte[] readEncrypted() throws java.io.IOException
	{
		if (in != null)
		{
			return CliSupport.readData(in);
		}
		String base64 = CliSupport.resolveText(text, textStdin).trim();
		try
		{
			return Base64.getDecoder().decode(base64);
		}
		catch (IllegalArgumentException notBase64)
		{
			throw new IllegalArgumentException(
				"the text to decrypt is not the base64 that 'encrypt' prints: "
					+ notBase64.getMessage(),
				notBase64);
		}
	}
}
