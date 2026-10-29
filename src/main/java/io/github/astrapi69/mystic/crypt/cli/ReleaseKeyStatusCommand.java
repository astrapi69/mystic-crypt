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

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;

import io.github.astrapi69.mystic.crypt.gnupg.GnuPgHome;
import io.github.astrapi69.mystic.crypt.gnupg.KeyRingState;
import io.github.astrapi69.mystic.crypt.gnupg.KeyState;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Prints what a GnuPG home holds: every key with its use, algorithm, creation, expiry and whether
 * its secret part is in the home or offline, and for every primary key whether gpg keeps a
 * revocation certificate that verifies against it.
 * <p>
 * Exit codes: 0 the home was read (and the key named with {@code --key} is in it), 1 the named key
 * is not in the home, 2 the home cannot be read.
 */
@Command(name = "status", mixinStandardHelpOptions = true, //
	description = "Show the keys of a GnuPG home: use, expiry, whether each secret part is here "
		+ "or offline, and the revocation certificate. Reads only. Exit codes: 0 read, 1 the "
		+ "key named with --key is not in the home, 2 the home cannot be read.")
public class ReleaseKeyStatusCommand implements Callable<Integer>
{

	/**
	 * Instantiates a new {@link ReleaseKeyStatusCommand}.
	 * <p>
	 * Declared explicitly, and public, because picocli builds this subcommand reflectively through
	 * its default factory when {@link MysticCryptCli} dispatches to it; the class must therefore
	 * keep an accessible no-argument constructor.
	 */
	public ReleaseKeyStatusCommand()
	{
	}

	@Option(names = "--home", paramLabel = "DIR", description = "The GnuPG home to read "
		+ "(default: GNUPGHOME, else ~/.gnupg).")
	Path home;

	@Option(names = "--key", paramLabel = "FINGERPRINT", description = "Show only this "
		+ "certificate: the fingerprint or the long key id of its primary key.")
	String key;

	@Option(names = "--json", description = "Print the same facts as JSON, for scripts.")
	boolean json;

	@Override
	public Integer call()
	{
		Path gnuPgHome = home != null
			? home
			: GnuPgHome.defaultHome(System.getenv(), System.getProperty("user.home"));
		List<KeyRingState> certificates;
		try
		{
			certificates = GnuPgHome.read(gnuPgHome);
		}
		catch (IOException unreadable)
		{
			System.err.println(CliSupport
				.error("cannot read the GnuPG home " + gnuPgHome + ": " + unreadable.getMessage()));
			return 2;
		}
		if (key != null)
		{
			Optional<KeyRingState> found = GnuPgHome.find(certificates, key);
			if (found.isEmpty())
			{
				System.err.println(CliSupport.error("the key " + key + " is not in " + gnuPgHome));
				return 1;
			}
			certificates = List.of(found.get());
		}
		System.out.println(json
			? ReleaseKeyJson.of(gnuPgHome, certificates)
			: readable(gnuPgHome, certificates, LocalDate.now(ZoneOffset.UTC)));
		return 0;
	}

	/**
	 * The readable report: the home, then per certificate its user ID, one line per key and the
	 * revocation certificate
	 */
	static String readable(final Path gnuPgHome, final List<KeyRingState> certificates,
		final LocalDate today)
	{
		StringBuilder report = new StringBuilder();
		report.append("GnuPG home ").append(gnuPgHome).append(": ").append(certificates.size())
			.append(" certificate(s)\n");
		for (KeyRingState certificate : certificates)
		{
			report.append('\n').append(certificate.fingerprint()).append("  ")
				.append(certificate.userId()).append('\n');
			for (KeyState keyState : certificate.keys())
			{
				report.append("  ").append(lineOf(keyState, today)).append('\n');
			}
			report.append("  revocation certificate: ")
				.append(certificate.revocationCertificate().name().toLowerCase().replace('_', ' '));
			report.append('\n');
		}
		return report.toString().stripTrailing();
	}

	private static String lineOf(final KeyState keyState, final LocalDate today)
	{
		return String.format("%-7s  %s  %-9s  %-6s  created %s  expires %-18s  secret %s",
			keyState.primary() ? "primary" : "subkey", keyState.fingerprint(), keyState.algorithm(),
			"[" + keyState.usage() + "]", dayOf(keyState.created()),
			expiryOf(keyState.expires(), today), keyState.secret().name().toLowerCase());
	}

	private static String expiryOf(final Instant expires, final LocalDate today)
	{
		if (expires == null)
		{
			return "never";
		}
		LocalDate day = dayOf(expires);
		return day.isBefore(today) ? "expired " + day : day.toString();
	}

	private static LocalDate dayOf(final Instant instant)
	{
		return LocalDate.ofInstant(instant, ZoneOffset.UTC);
	}
}
