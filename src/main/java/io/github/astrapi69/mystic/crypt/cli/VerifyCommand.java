/**
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
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Verifies a password against an encoded Argon2id/PBKDF2 hash. Exit code 0 means the password
 * matches, 1 means it does not.
 */
@Command(name = "verify", mixinStandardHelpOptions = true, //
	description = "Verify a password against an encoded Argon2id/PBKDF2 hash. "
		+ "Exit code 0 = matches, 1 = does not match.")
public class VerifyCommand implements Callable<Integer>
{

	@Option(names = { "-a",
			"--algorithm" }, defaultValue = "argon2id", description = "Hashing algorithm: ${COMPLETION-CANDIDATES} (default: argon2id).")
	PasswordAlgorithm algorithm;

	@Option(names = "--hash", required = true, description = "The encoded hash to verify against.")
	String hash;

	@Option(names = "--password", description = "The password to verify. Prefer --password-stdin.")
	String password;

	@Option(names = "--password-stdin", description = "Read the password from the first line of standard input.")
	boolean passwordStdin;

	@Override
	public Integer call()
	{
		String plainPassword = CliSupport.resolvePassword(password, passwordStdin);
		PasswordEncryptor passwordEncryptor = PasswordEncryptor.getInstance();
		boolean matches = algorithm == PasswordAlgorithm.pbkdf2
			? passwordEncryptor.matchPbkdf2(plainPassword, hash)
			: passwordEncryptor.matchArgon2id(plainPassword, hash);
		System.out.println(matches ? "matches" : "does not match");
		return matches ? 0 : 1;
	}
}
