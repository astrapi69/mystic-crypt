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

import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.Callable;

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
	description = "Compute the checksum (message digest) of a file.")
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

	@Option(names = { "-a", "--algorithm" }, defaultValue = "SHA-256", //
		description = "Digest algorithm (a JDK name), e.g. MD5, SHA-1, SHA-256, SHA-512 "
			+ "(default: SHA-256).")
	String algorithm;

	@Parameters(index = "0", paramLabel = "FILE", description = "The file to checksum.")
	File file;

	@Override
	public Integer call() throws Exception
	{
		MessageDigest messageDigest;
		try
		{
			messageDigest = MessageDigest.getInstance(algorithm);
		}
		catch (NoSuchAlgorithmException exception)
		{
			throw new IllegalArgumentException("unknown digest algorithm '" + algorithm
				+ "'. Use a JDK digest name such as MD5, SHA-1, SHA-256 or SHA-512.");
		}
		byte[] digest = messageDigest.digest(Files.readAllBytes(file.toPath()));
		System.out.println(CliSupport.HEX.formatHex(digest));
		return 0;
	}
}
