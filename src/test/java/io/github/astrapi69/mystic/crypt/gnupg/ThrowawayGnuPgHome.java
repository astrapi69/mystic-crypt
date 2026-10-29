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
package io.github.astrapi69.mystic.crypt.gnupg;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * A GnuPG home in a temporary directory, written by gpg itself: the keys the reader is tested on
 * are exactly what gpg writes, not what a test believes gpg writes. Every call names the directory
 * with {@code --homedir}, so the real keyring of the machine is never touched, and {@link #close()}
 * stops the agent gpg started for it.
 * <p>
 * The passphrase is made up per run, so nothing here reads as a credential.
 */
public final class ThrowawayGnuPgHome implements AutoCloseable
{

	/** How long one gpg call may take; generating an RSA key is the slowest, a few seconds */
	private static final long TIMEOUT_SECONDS = 120;

	private final Path directory;

	private final Path log;

	private final String passphrase = "throwaway-" + UUID.randomUUID();

	private ThrowawayGnuPgHome(final Path directory)
	{
		this.directory = directory;
		this.log = directory.resolveSibling(directory.getFileName() + "-gpg.log");
	}

	/**
	 * Creates an empty GnuPG home, readable by its owner only, as gpg requires
	 *
	 * @param directory
	 *            the directory, created when it does not exist
	 * @return the home
	 */
	public static ThrowawayGnuPgHome create(final Path directory) throws IOException
	{
		Files.createDirectories(directory);
		Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
		return new ThrowawayGnuPgHome(directory);
	}

	public Path directory()
	{
		return directory;
	}

	/**
	 * Generates a primary key whose secret part is protected with this home's passphrase
	 *
	 * @return the fingerprint of the new primary key
	 */
	public String generate(final String userId, final String algorithm, final String usage,
		final String expiry) throws IOException
	{
		gpg(passphrase, "--quick-gen-key", userId, algorithm, usage, expiry);
		return primaryFingerprintOf(userId);
	}

	/**
	 * Generates a primary key whose secret part is not protected at all, which gpg writes as a
	 * {@code private-key} rather than a {@code protected-private-key}
	 *
	 * @return the fingerprint of the new primary key
	 */
	String generateUnprotected(final String userId, final String algorithm, final String usage)
		throws IOException
	{
		gpg("", "--quick-gen-key", userId, algorithm, usage, "0");
		return primaryFingerprintOf(userId);
	}

	/** Adds a subkey to the key with the given fingerprint */
	public void addSubkey(final String fingerprint, final String algorithm, final String usage,
		final String expiry) throws IOException
	{
		gpg(passphrase, "--quick-add-key", fingerprint, algorithm, usage, expiry);
	}

	/**
	 * Takes the primary key offline the way the release key is: its secret part leaves this home,
	 * the subkeys stay. The file gpg keeps it in is deleted, which is what is left once it was
	 * moved to an offline medium
	 */
	public void takePrimaryOffline(final String fingerprint) throws IOException
	{
		for (String[] fields : colons("--with-keygrip", "--list-secret-keys", fingerprint))
		{
			if ("grp".equals(fields[0]))
			{
				Files.delete(directory.resolve("private-keys-v1.d").resolve(fields[9] + ".key"));
				return;
			}
		}
		throw new IOException("gpg names no keygrip for " + fingerprint);
	}

	/** The public part of the key with the given fingerprint, as gpg exports it */
	byte[] exportPublicKey(final String fingerprint) throws IOException
	{
		return run(null, "--export", fingerprint);
	}

	/** The public part of the key with the given fingerprint, armored */
	public byte[] exportArmoredPublicKey(final String fingerprint) throws IOException
	{
		return run(null, "--armor", "--export", fingerprint);
	}

	/** An armored detached signature over the given bytes, made with the given key */
	public byte[] detachSign(final String fingerprint, final byte[] content) throws IOException
	{
		Path document = directory.resolveSibling(directory.getFileName() + "-signed.txt");
		Files.write(document, content);
		gpg(passphrase, "--local-user", fingerprint + "!", "--armor", "--detach-sign", "--output",
			document + ".asc", document.toString());
		return Files.readAllBytes(Path.of(document + ".asc"));
	}

	/**
	 * Imports an X.509 certificate with gpgsm, which keeps it in the same {@code pubring.kbx} as
	 * gpg's OpenPGP certificates
	 */
	public void importX509(final Path certificate) throws IOException
	{
		execute(null, List.of("gpgsm", "--homedir", directory.toString(), "--batch", "--no-tty",
			"--disable-dirmngr", "--import", certificate.toString()));
	}

	/** Imports keys gpg exported, here without any secret part */
	void importKeys(final byte[] exported) throws IOException
	{
		run(exported, "--import");
	}

	/**
	 * What gpg itself says about every key in this home, the answer the reader is measured against
	 *
	 * @return one entry per primary key and subkey that gpg lists
	 */
	List<ListedKey> listKeys() throws IOException
	{
		List<String> withSecret = new ArrayList<>();
		for (ListedKey listed : listed("--list-secret-keys"))
		{
			if (listed.secretHere())
			{
				withSecret.add(listed.fingerprint());
			}
		}
		List<ListedKey> keys = new ArrayList<>();
		for (ListedKey listed : listed("--list-keys"))
		{
			keys.add(new ListedKey(listed.fingerprint(), listed.primary(), listed.algorithm(),
				listed.bits(), listed.curve(), listed.capabilities(), listed.created(),
				listed.expires(), withSecret.contains(listed.fingerprint())));
		}
		return keys;
	}

	private List<ListedKey> listed(final String command) throws IOException
	{
		List<ListedKey> keys = new ArrayList<>();
		String[] pending = null;
		for (String[] fields : colons("--with-subkey-fingerprint", command))
		{
			if (List.of("pub", "sub", "sec", "ssb").contains(fields[0]))
			{
				pending = fields;
			}
			else if ("fpr".equals(fields[0]) && pending != null)
			{
				keys.add(listedKey(pending, fields[9]));
				pending = null;
			}
		}
		return keys;
	}

	private static ListedKey listedKey(final String[] fields, final String fingerprint)
	{
		StringBuilder capabilities = new StringBuilder();
		fields[11].chars().filter(Character::isLowerCase).forEach(capabilities::appendCodePoint);
		return new ListedKey(fingerprint, "pub".equals(fields[0]) || "sec".equals(fields[0]),
			Integer.parseInt(fields[3]), Integer.parseInt(fields[2]),
			fields.length > 16 ? fields[16] : "", capabilities.toString(),
			Instant.ofEpochSecond(Long.parseLong(fields[5])),
			fields[6].isEmpty() ? null : Instant.ofEpochSecond(Long.parseLong(fields[6])),
			fields.length > 14 && "+".equals(fields[14]));
	}

	private String primaryFingerprintOf(final String userId) throws IOException
	{
		for (String[] fields : colons("--list-keys", "=" + userId))
		{
			if ("fpr".equals(fields[0]))
			{
				return fields[9];
			}
		}
		throw new IOException("gpg lists no key for " + userId);
	}

	private List<String[]> colons(final String... command) throws IOException
	{
		List<String> arguments = new ArrayList<>(List.of("--with-colons"));
		arguments.addAll(List.of(command));
		String output = new String(run(null, arguments.toArray(String[]::new)),
			StandardCharsets.UTF_8);
		List<String[]> lines = new ArrayList<>();
		for (String line : output.split("\n"))
		{
			lines.add(line.split(":", -1));
		}
		return lines;
	}

	private void gpg(final String passphraseToUse, final String... command) throws IOException
	{
		List<String> arguments = new ArrayList<>(
			List.of("--pinentry-mode", "loopback", "--passphrase-fd", "0"));
		arguments.addAll(List.of(command));
		run((passphraseToUse + "\n").getBytes(StandardCharsets.UTF_8),
			arguments.toArray(String[]::new));
	}

	private byte[] run(final byte[] input, final String... command) throws IOException
	{
		List<String> arguments = new ArrayList<>(
			List.of("gpg", "--homedir", directory.toString(), "--batch", "--no-tty", "--yes"));
		arguments.addAll(List.of(command));
		return execute(input, arguments);
	}

	private byte[] execute(final byte[] input, final List<String> arguments) throws IOException
	{
		ProcessBuilder builder = new ProcessBuilder(arguments)
			.redirectError(ProcessBuilder.Redirect.appendTo(log.toFile()));
		builder.environment().put("LC_ALL", "C");
		builder.environment().remove("GNUPGHOME");
		Process process = builder.start();
		try (OutputStream in = process.getOutputStream())
		{
			if (input != null)
			{
				in.write(input);
			}
		}
		byte[] output = process.getInputStream().readAllBytes();
		awaitSuccess(process, arguments);
		return output;
	}

	private void awaitSuccess(final Process process, final List<String> arguments)
		throws IOException
	{
		try
		{
			if (!process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS))
			{
				process.destroyForcibly();
				throw new IOException(
					"did not finish within " + TIMEOUT_SECONDS + " seconds: " + arguments);
			}
		}
		catch (InterruptedException exception)
		{
			Thread.currentThread().interrupt();
			throw new IOException("interrupted while waiting for " + arguments, exception);
		}
		if (process.exitValue() != 0)
		{
			throw new IOException("exit code " + process.exitValue() + " from " + arguments
				+ ", its standard error is in " + log);
		}
	}

	/** Stops the agent gpg started for this home, so no process outlives the test */
	@Override
	public void close() throws IOException
	{
		execute(null, List.of("gpgconf", "--homedir", directory.toString(), "--kill", "all"));
	}

	/**
	 * One key as gpg lists it with {@code --with-colons}
	 *
	 * @param fingerprint
	 *            the fingerprint
	 * @param primary
	 *            whether it is the primary key
	 * @param algorithm
	 *            the OpenPGP algorithm number
	 * @param bits
	 *            the size gpg names
	 * @param curve
	 *            the curve gpg names, empty for RSA
	 * @param capabilities
	 *            the key's own capabilities in gpg's letters and order, for example {@code sc}
	 * @param created
	 *            when it was created
	 * @param expires
	 *            when it expires, null for never
	 * @param secretHere
	 *            whether gpg has its secret part in this home
	 */
	record ListedKey(String fingerprint, boolean primary, int algorithm, int bits, String curve,
		String capabilities, Instant created, Instant expires, boolean secretHere) {
	}
}
