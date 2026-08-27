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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

import io.github.astrapi69.mystic.crypt.secret.SecretShare;
import io.github.astrapi69.mystic.crypt.secret.SecretSharing;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Splits a secret into shares and puts it back together, exposing the library's Shamir secret
 * sharing on the command line.
 */
@Command(name = "share", mixinStandardHelpOptions = true, //
	description = "Split a secret into shares and combine them back (Shamir secret sharing).", //
	subcommands = { ShareCommand.SplitCommand.class, ShareCommand.CombineCommand.class })
public class ShareCommand implements Runnable
{

	/**
	 * Instantiates a new {@link ShareCommand}.
	 * <p>
	 * Declared explicitly, and public, because picocli builds this subcommand reflectively through
	 * its default factory when {@link MysticCryptCli} dispatches to it; the class must therefore
	 * keep an accessible no-argument constructor.
	 */
	public ShareCommand()
	{
	}

	@Override
	public void run()
	{
		CommandLine.usage(this, System.out);
	}

	/**
	 * Splits a secret into shares, one share per line.
	 */
	@Command(name = "split", mixinStandardHelpOptions = true, //
		description = "Split a secret into shares, one per line. Exit code 0 = split, 2 = error.")
	public static class SplitCommand implements Callable<Integer>
	{

		/**
		 * Instantiates a new {@link SplitCommand}.
		 * <p>
		 * Declared explicitly, and public, because picocli builds this subcommand reflectively
		 * through its default factory; the class must keep an accessible no-argument constructor.
		 */
		public SplitCommand()
		{
		}

		@Option(names = "--secret", description = "The secret to split. Prefer --secret-stdin to keep it out of the process arguments.")
		String secret;

		@Option(names = "--secret-stdin", description = "Read the secret from the first line of standard input.")
		boolean secretStdin;

		@Option(names = "--file", description = "Split the contents of this file instead of a text secret.")
		File file;

		@Option(names = { "-t",
				"--threshold" }, required = true, description = "How many shares are needed to reconstruct the secret.")
		int threshold;

		@Option(names = { "-n",
				"--shares" }, required = true, description = "How many shares to produce.")
		int shares;

		@Option(names = { "-o",
				"--out" }, description = "Write the shares to this file instead of printing them.")
		File out;

		@Override
		public Integer call()
		{
			CliSupport.refuseDashAsPath(out, "--out", CliSupport.PASS_A_PATH);
			try
			{
				byte[] secretBytes = readSecret();
				List<SecretShare> split = SecretSharing.split(secretBytes, threshold, shares);
				StringBuilder lines = new StringBuilder();
				for (SecretShare share : split)
				{
					lines.append(share.encode()).append(System.lineSeparator());
				}
				if (out != null)
				{
					Files.writeString(out.toPath(), lines.toString(), StandardCharsets.UTF_8);
					System.out.println("wrote " + split.size() + " shares to " + out.getPath()
						+ "; any " + threshold + " of them reconstruct the secret");
				}
				else
				{
					System.out.print(lines);
				}
				return 0;
			}
			catch (Exception exception)
			{
				System.err.println(CliSupport.error(exception.getMessage()));
				return 2;
			}
		}

		private byte[] readSecret() throws java.io.IOException
		{
			if (file != null)
			{
				return CliSupport.readData(file);
			}
			if (secretStdin)
			{
				return CliSupport.resolvePassword(null, true).getBytes(StandardCharsets.UTF_8);
			}
			if (secret == null)
			{
				throw new IllegalArgumentException(
					"a secret is required: pass --secret, --secret-stdin or --file");
			}
			return secret.getBytes(StandardCharsets.UTF_8);
		}
	}

	/**
	 * Combines shares back into the secret.
	 */
	@Command(name = "combine", mixinStandardHelpOptions = true, //
		description = "Combine shares back into the secret. Exit code 0 = combined, "
			+ "1 = the shares do not reconstruct a secret, 2 = error.")
	public static class CombineCommand implements Callable<Integer>
	{

		/**
		 * Instantiates a new {@link CombineCommand}.
		 * <p>
		 * Declared explicitly, and public, because picocli builds this subcommand reflectively
		 * through its default factory; the class must keep an accessible no-argument constructor.
		 */
		public CombineCommand()
		{
		}

		@Option(names = "--share", description = "A share line, repeatable.")
		List<String> shareLines = new ArrayList<>();

		@Option(names = "--file", description = "Read the share lines from this file, one per line.")
		File file;

		@Option(names = { "-o",
				"--out" }, description = "Write the secret to this file instead of printing it.")
		File out;

		@Override
		public Integer call()
		{
			CliSupport.refuseDashAsPath(out, "--out", CliSupport.LEAVE_IT_OUT);
			// the two phases are kept apart because they answer different questions: reading the
			// shares can fail before there is anything to reconstruct (exit 2), while combining
			// them can succeed as an operation and still not produce a secret (exit 1)
			List<SecretShare> shares;
			try
			{
				shares = readShares();
			}
			catch (Exception cannotEvenRead)
			{
				System.err.println(CliSupport.error(cannotEvenRead.getMessage()));
				return 2;
			}
			try
			{
				byte[] secret = SecretSharing.combine(shares);
				if (out != null)
				{
					Files.write(out.toPath(), secret);
					System.out.println("wrote the reconstructed secret to " + out.getPath());
				}
				else
				{
					System.out.println(new String(secret, StandardCharsets.UTF_8));
				}
				return 0;
			}
			catch (IllegalArgumentException cannotReconstruct)
			{
				System.err.println(CliSupport.error(cannotReconstruct.getMessage()));
				return 1;
			}
			catch (Exception exception)
			{
				System.err.println(CliSupport.error(exception.getMessage()));
				return 2;
			}
		}

		private List<SecretShare> readShares() throws java.io.IOException
		{
			List<String> lines = new ArrayList<>(shareLines);
			if (file != null)
			{
				for (String line : Files.readAllLines(file.toPath(), StandardCharsets.UTF_8))
				{
					if (!line.isBlank())
					{
						lines.add(line);
					}
				}
			}
			if (lines.isEmpty())
			{
				throw new IllegalArgumentException(
					"no shares were given: pass --share <line> (repeatable) or --file <file>");
			}
			List<SecretShare> shares = new ArrayList<>(lines.size());
			for (String line : lines)
			{
				shares.add(SecretShare.decode(line));
			}
			return shares;
		}
	}
}
