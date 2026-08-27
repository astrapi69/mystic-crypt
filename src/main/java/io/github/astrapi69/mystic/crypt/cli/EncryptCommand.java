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
import java.util.concurrent.Callable;

import io.github.astrapi69.mystic.crypt.pw.PassphraseCryptor;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Encrypts a file or a piece of text with a passphrase, using AES-GCM over a key derived with
 * PBKDF2-HMAC-SHA256 and a salt that is fresh for every run.
 */
@Command(name = "encrypt", mixinStandardHelpOptions = true, //
	description = "Encrypt a file or a text with a passphrase (AES-GCM, PBKDF2-HMAC-SHA256). "
		+ "Exit code 0 = encrypted, 2 = error.")
public class EncryptCommand implements Callable<Integer>
{

	/**
	 * Instantiates a new {@link EncryptCommand}.
	 * <p>
	 * Declared explicitly, and public, because picocli builds this subcommand reflectively through
	 * its default factory when {@link MysticCryptCli} dispatches to it; the class must therefore
	 * keep an accessible no-argument constructor.
	 */
	public EncryptCommand()
	{
	}

	@Option(names = { "-i",
			"--in" }, description = "The file to encrypt, or '-' for standard input.")
	File in;

	@Option(names = { "-o",
			"--out" }, description = "The file to write. Without it the result is printed as base64.")
	File out;

	@Option(names = { "-t", "--text" }, description = "The text to encrypt instead of a file.")
	String text;

	@Option(names = "--text-stdin", description = "Read the text to encrypt from standard input.")
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
			byte[] plain = PassphraseCryptSupport.readInput(in, text, textStdin);
			char[] resolvedPassphrase = PassphraseCryptSupport.resolvePassphrase(passphrase,
				passphraseStdin);
			byte[] encrypted = PassphraseCryptor.encrypt(resolvedPassphrase, plain);
			String printed = PassphraseCryptSupport.writeOutput(out, encrypted,
				PassphraseCryptSupport::asBase64);
			if (printed == null)
			{
				System.out.println("encrypted " + plain.length + " bytes to " + out.getPath());
			}
			else
			{
				System.out.println(printed);
			}
			return 0;
		}
		catch (Exception exception)
		{
			System.err.println(CliSupport.error(exception.getMessage()));
			return 2;
		}
	}
}
