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
 * Hashes a password with Argon2id or PBKDF2 and prints the encoded hash.
 */
@Command(name = "hash", mixinStandardHelpOptions = true, //
	description = "Hash a password with Argon2id or PBKDF2 and print the encoded hash.")
public class HashCommand implements Callable<Integer>
{

	@Option(names = { "-a",
			"--algorithm" }, defaultValue = "argon2id", description = "Hashing algorithm: ${COMPLETION-CANDIDATES} (default: argon2id).")
	PasswordAlgorithm algorithm;

	@Option(names = "--password", description = "The password to hash. Prefer --password-stdin to keep it out of the process arguments.")
	String password;

	@Option(names = "--password-stdin", description = "Read the password from the first line of standard input.")
	boolean passwordStdin;

	@Override
	public Integer call()
	{
		String plainPassword = CliSupport.resolvePassword(password, passwordStdin);
		PasswordEncryptor passwordEncryptor = PasswordEncryptor.getInstance();
		String encodedHash = algorithm == PasswordAlgorithm.pbkdf2
			? passwordEncryptor.hashPasswordPbkdf2(plainPassword)
			: passwordEncryptor.hashPasswordArgon2id(plainPassword);
		System.out.println(encodedHash);
		return 0;
	}
}
