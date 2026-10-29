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
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Where a command gets a secret from (#214, rule in library-first.md): the first line of standard
 * input, or a prompt in a terminal that does not echo what is typed. An argument is visible to
 * every process on the machine and lands in shell history; the arguments that held a secret still
 * work through 13.x, with a warning on standard error, and go away in 14.0.
 *
 * @param argument
 *            the option that is going away, for example {@code --password}
 * @param stdinFlag
 *            the option that reads standard input, for example {@code --password-stdin}
 * @param what
 *            what the secret is, for example {@code password}
 */
record SecretInput(String argument, String stdinFlag, String what) {

	/** The password of {@code hash} and {@code verify} */
	static final SecretInput PASSWORD = new SecretInput("--password", "--password-stdin",
		"password");

	/** The passphrase of {@code encrypt} and {@code decrypt} */
	static final SecretInput PASSPHRASE = new SecretInput("--passphrase", "--passphrase-stdin",
		"passphrase");

	/** The key store password of {@code keystore} */
	static final SecretInput KEY_STORE_PASSWORD = new SecretInput("--password", "--password-stdin",
		"key store password");

	/** The MAC key of {@code checksum --hmac} */
	static final SecretInput MAC_KEY = new SecretInput("--key", "--key-stdin", "MAC key");

	/** The secret of {@code share split} */
	static final SecretInput SHARED_SECRET = new SecretInput("--secret", "--secret-stdin",
		"secret");

	/**
	 * The secret, from standard input, from the argument that is going away, or from a prompt in a
	 * terminal, in this order
	 *
	 * @param value
	 *            the argument's value, null when it was not given
	 * @param fromStandardInput
	 *            whether the standard input flag was given
	 * @return the secret
	 * @throws IllegalArgumentException
	 *             when standard input is empty, or nothing was given and there is no terminal to
	 *             ask in
	 */
	char[] resolve(final String value, final boolean fromStandardInput)
	{
		if (fromStandardInput)
		{
			return firstLineOfStandardInput().toCharArray();
		}
		if (value != null && !value.isEmpty())
		{
			System.err.println(warning());
			return value.toCharArray();
		}
		return askInTerminal();
	}

	/**
	 * The secret as text, for the commands whose library call takes a string
	 *
	 * @param value
	 *            the argument's value, null when it was not given
	 * @param fromStandardInput
	 *            whether the standard input flag was given
	 * @return the secret
	 */
	String resolveText(final String value, final boolean fromStandardInput)
	{
		return new String(resolve(value, fromStandardInput));
	}

	/** The line printed when the secret came as an argument */
	String warning()
	{
		return CliSupport.warning(argument + " puts the " + what
			+ " into the process arguments, where other processes and the shell history can read "
			+ "it. Use " + stdinFlag + ", or leave both out to be asked in a terminal. " + argument
			+ " goes away in 14.0.");
	}

	private String firstLineOfStandardInput()
	{
		try
		{
			String line = new BufferedReader(
				new InputStreamReader(System.in, StandardCharsets.UTF_8)).readLine();
			if (line == null)
			{
				throw new IllegalArgumentException(
					"no " + what + " was provided on standard input");
			}
			return line;
		}
		catch (IOException exception)
		{
			throw new IllegalArgumentException(
				"could not read the " + what + " from standard input: " + exception.getMessage(),
				exception);
		}
	}

	/**
	 * Asks in the terminal without echoing. A JVM without a terminal - a pipe, a test, a CI job -
	 * has nobody to ask, and is told the option that works there instead
	 */
	private char[] askInTerminal()
	{
		return Optional.ofNullable(System.console()).filter(Console::isTerminal)
			.map(console -> console.readPassword("%s: ", what))
			.orElseThrow(() -> new IllegalArgumentException("a " + what + " is required: pass "
				+ stdinFlag + ", or run in a terminal to be asked for it"));
	}
}
