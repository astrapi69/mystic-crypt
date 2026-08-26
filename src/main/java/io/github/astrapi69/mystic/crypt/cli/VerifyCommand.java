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

import java.util.concurrent.Callable;

import io.github.astrapi69.mystic.crypt.pw.PasswordEncryptor;
import io.github.astrapi69.mystic.crypt.pw.PasswordHashFormat;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Verifies a password against an encoded hash, reading from the hash which algorithm produced it.
 * Exit code 0 means the password matches, 1 means it does not, and 2 means the hash belongs to no
 * algorithm this tool knows.
 */
@Command(name = "verify", mixinStandardHelpOptions = true, //
	description = "Verify a password against an encoded hash. The algorithm is read from "
		+ "the hash itself. Exit code 0 = matches, 1 = does not match, 2 = the hash is not of a "
		+ "known algorithm.")
public class VerifyCommand implements Callable<Integer>
{

	/**
	 * Instantiates a new {@link VerifyCommand}.
	 * <p>
	 * Declared explicitly, and public, because picocli builds this subcommand reflectively through
	 * its default factory when {@link MysticCryptCli} dispatches to it; the class must therefore
	 * keep an accessible no-argument constructor.
	 */
	public VerifyCommand()
	{
	}

	@Option(names = "--hash", required = true, description = "The encoded hash to verify against. "
		+ "Which algorithm produced it is read from the hash itself.")
	String hash;

	@Option(names = "--password", description = "The password to verify. Prefer --password-stdin.")
	String password;

	@Option(names = "--password-stdin", description = "Read the password from the first line of standard input.")
	boolean passwordStdin;

	@Override
	public Integer call()
	{
		try
		{
			String plainPassword = CliSupport.resolvePassword(password, passwordStdin);
			PasswordHashFormat format = PasswordHashFormat.of(hash);
			boolean matches = PasswordEncryptor.getInstance().matchEncodedHash(plainPassword, hash);
			System.out.println((matches ? "matches" : "does not match") + " (" + format + ")");
			return matches ? 0 : 1;
		}
		catch (Exception exception)
		{
			// an encoding that belongs to no known algorithm is not "the password does not match";
			// answering 1 there would send the reader after the password instead of after the hash
			System.err.println(CliSupport.error(exception.getMessage()));
			return 2;
		}
	}
}
