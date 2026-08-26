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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.Callable;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

/**
 * Computes and prints the checksum (message digest) of a file with a chosen JDK digest algorithm.
 * <p>
 * This uses the JDK-native {@link MessageDigest} on purpose: the {@code checksum-up} library's
 * {@code FileChecksumExtensions.getChecksum(File, Algorithm)} pulls a different crypt-api
 * {@code Algorithm} across the module boundary and fails to resolve here. Once a checksum-up
 * release built against the current crypt-api is available, this command can switch to it to also
 * offer the non-cryptographic digests (CRC32, Adler32).
 */
@Command(name = "checksum", mixinStandardHelpOptions = true, //
	description = "Compute the checksum of a file: a plain digest, which answers whether the "
		+ "file changed, or with --hmac a keyed MAC, which answers whether it changed at the "
		+ "hands of someone without the key.")
public class ChecksumCommand implements Callable<Integer>
{

	/**
	 * Instantiates a new {@link ChecksumCommand}.
	 * <p>
	 * Declared explicitly, and public, because picocli builds this subcommand reflectively through
	 * its default factory when {@link MysticCryptCli} dispatches to it; the class must therefore
	 * keep an accessible no-argument constructor.
	 */
	public ChecksumCommand()
	{
	}

	/** The digest used when none is named. */
	private static final String DEFAULT_DIGEST_ALGORITHM = "SHA-256";

	/** The MAC used when --hmac is given without naming one. */
	private static final String DEFAULT_MAC_ALGORITHM = "HmacSHA256";

	@Option(names = { "-a", "--algorithm" }, //
		description = "Digest algorithm (a JDK name), e.g. MD5, SHA-1, SHA-256, SHA-512 "
			+ "(default: SHA-256). With --hmac a MAC name such as HmacSHA256 (default: HmacSHA256).")
	String algorithm;

	@Option(names = "--hmac", description = "Compute a keyed MAC instead of a plain digest, which "
		+ "answers whether the file was changed by someone who does not hold the key.")
	boolean hmac;

	@Option(names = "--key", description = "The MAC key. Prefer --key-stdin to keep it out of the "
		+ "process arguments.")
	String key;

	@Option(names = "--key-stdin", description = "Read the MAC key from the first line of standard input.")
	boolean keyStdin;

	@Parameters(index = "0", paramLabel = "FILE", description = "The file to checksum.")
	File file;

	@Override
	public Integer call() throws Exception
	{
		try
		{
			byte[] content = Files.readAllBytes(file.toPath());
			if (hmac)
			{
				String macAlgorithm = algorithm == null ? DEFAULT_MAC_ALGORITHM : algorithm;
				byte[] mac = keyedDigest(content, macAlgorithm);
				print(mac, macAlgorithm + " keyed digest");
				return 0;
			}
			String digestAlgorithm = algorithm == null ? DEFAULT_DIGEST_ALGORITHM : algorithm;
			print(plainDigest(content, digestAlgorithm), digestAlgorithm + " digest");
			return 0;
		}
		catch (IllegalArgumentException wrongInput)
		{
			System.err.println(CliSupport.error(wrongInput.getMessage()));
			return 2;
		}
	}

	/**
	 * Prints the result the way {@code sha256sum} does, the value first so it stays the first
	 * whitespace-separated field, followed by what question it answers.
	 *
	 * @param result
	 *            the digest or MAC bytes
	 * @param label
	 *            what was computed
	 */
	private void print(final byte[] result, final String label)
	{
		System.out
			.println(CliSupport.HEX.formatHex(result) + "  " + label + " of " + file.getPath());
	}

	private static byte[] plainDigest(final byte[] content, final String digestAlgorithm)
	{
		try
		{
			return MessageDigest.getInstance(digestAlgorithm).digest(content);
		}
		catch (NoSuchAlgorithmException unknown)
		{
			throw new IllegalArgumentException("unknown digest algorithm '" + digestAlgorithm
				+ "'. Use a JDK digest name such as MD5, SHA-1, SHA-256 or SHA-512.");
		}
	}

	private byte[] keyedDigest(final byte[] content, final String macAlgorithm)
	{
		String macKey = CliSupport.resolvePassword(key, keyStdin);
		try
		{
			Mac mac = Mac.getInstance(macAlgorithm);
			mac.init(new SecretKeySpec(macKey.getBytes(StandardCharsets.UTF_8), macAlgorithm));
			return mac.doFinal(content);
		}
		catch (NoSuchAlgorithmException unknown)
		{
			throw new IllegalArgumentException("unknown MAC algorithm '" + macAlgorithm
				+ "'. Use a JDK MAC name such as HmacSHA256, HmacSHA512 or HmacSHA3-256. A plain "
				+ "digest name like SHA-256 is not one: drop --hmac to compute that instead.");
		}
		catch (InvalidKeyException rejected)
		{
			throw new IllegalArgumentException("the MAC key was rejected: " + rejected.getMessage(),
				rejected);
		}
	}
}
