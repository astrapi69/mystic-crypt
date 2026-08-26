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


import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

import picocli.CommandLine;
import picocli.CommandLine.Command;

/**
 * Root command of the mystic-crypt command-line interface. It bundles the individual crypto
 * operations as subcommands (password hashing, key generation, key encapsulation, checksums,
 * DER/PEM conversion, obfuscation, X.509 certificate creation, key store management and Ed25519 /
 * ML-DSA / SLH-DSA signatures), each a thin wrapper over the corresponding mystic-crypt / crypt-*
 * library API.
 * <p>
 * Run without a subcommand it prints the usage help.
 */
@Command(name = "mystic-crypt", mixinStandardHelpOptions = true, version = "mystic-crypt CLI 1.0", //
	description = "Command-line access to mystic-crypt: password hashing, key generation, key "
		+ "encapsulation (KEM), checksums, DER/PEM conversion, obfuscation, certificates, "
		+ "key store management and signatures.", //
	subcommands = { HashCommand.class, VerifyCommand.class, KeygenCommand.class, KemCommand.class,
			ChecksumCommand.class, DerToPemCommand.class, ObfuscateCommand.class,
			DisentangleCommand.class, CertificateCommand.class, KeystoreCommand.class,
			SignCommand.class, VerifySignatureCommand.class, EncryptCommand.class,
			DecryptCommand.class, ShareCommand.class, CommandLine.HelpCommand.class })
public class MysticCryptCli implements Runnable
{

	static
	{
		// several algorithms used by the subcommands (post-quantum KEM/signatures, certificate
		// signing) resolve through Bouncy Castle; register it once for the whole CLI, including
		// when
		// subcommands are invoked programmatically through the root command in tests
		SecurityProviderSupport.ensureBouncyCastle();
	}

	/**
	 * Instantiates a new {@link MysticCryptCli}.
	 * <p>
	 * Private on purpose: this class is only the CLI entry point. The single instance the command
	 * line needs is created inside {@link #execute(String...)}; picocli never builds the root
	 * command reflectively, it only builds the subcommands listed in the {@code @Command}
	 * annotation. Clients drive the CLI through {@link #execute(String...)} or
	 * {@link #main(String[])}.
	 */
	private MysticCryptCli()
	{
	}

	@Override
	public void run()
	{
		CommandLine.usage(this, System.out);
	}

	/**
	 * Runs the CLI with the given arguments and returns the exit code, without terminating the JVM.
	 * This is the testable core of {@link #main(String[])}.
	 *
	 * @param args
	 *            the command-line arguments
	 * @return the exit code
	 */
	public static int execute(String... args)
	{
		return new CommandLine(new MysticCryptCli()).execute(args);
	}

	/**
	 * Entry point of the command-line interface. Delegates to {@link #execute(String...)} and turns
	 * its return value into the process exit code, so that shells and scripts can branch on the
	 * result of a subcommand.
	 *
	 * @param args
	 *            the command-line arguments
	 */
	public static void main(String[] args)
	{
		System.exit(execute(args));
	}
}
