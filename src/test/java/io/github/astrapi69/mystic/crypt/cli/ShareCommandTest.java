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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import io.github.astrapi69.mystic.crypt.secret.SecretShare;

/**
 * Unit tests for the {@code share split} and {@code share combine} subcommands, driven through the
 * real command line.
 */
class ShareCommandTest extends AbstractCliTest
{

	private static final String SECRET = "a secret long enough to be split";

	private List<String> splitLines(int threshold, int shares)
	{
		assertEquals(0, run("share", "split", "--secret", SECRET, "-t", String.valueOf(threshold),
			"-n", String.valueOf(shares)));
		return out.lines().filter(line -> !line.isBlank()).toList();
	}

	@ParameterizedTest
	@CsvSource({ "2,2", "2,3", "3,5", "5,5" })
	void anyThresholdManySharesReconstructTheSecret(int threshold, int shares)
	{
		List<String> lines = splitLines(threshold, shares);
		assertEquals(shares, lines.size(), "split must print one line per share");

		String[] args = new String[1 + 2 * threshold];
		args[0] = "combine";
		for (int i = 0; i < threshold; i++)
		{
			args[1 + 2 * i] = "--share";
			args[2 + 2 * i] = lines.get(i);
		}
		String[] full = new String[args.length + 1];
		full[0] = "share";
		System.arraycopy(args, 0, full, 1, args.length);

		assertEquals(0, run(full), "stderr was: '" + err + "'");
		assertEquals(SECRET, out.trim());
	}

	@Test
	void fewerSharesThanTheThresholdSayeSoInsteadOfRebuildingNonsense()
	{
		List<String> lines = splitLines(3, 5);

		int exitCode = run("share", "combine", "--share", lines.get(0), "--share", lines.get(1));

		assertEquals(1, exitCode, "stderr was: '" + err + "'");
		assertTrue(err.contains("needs 3 shares"),
			"the message must say how many are needed, but was: '" + err + "'");
		assertEquals("", out.trim(), "no secret, right or wrong, may be printed");
	}

	@Test
	void sharesOfTwoDifferentSplitsAreRefusedRatherThanMixed()
	{
		List<String> firstSplit = splitLines(2, 3);
		List<String> secondSplit = splitLines(2, 3);
		assertNotEquals(SecretShare.decode(firstSplit.get(0)).getSplitId(),
			SecretShare.decode(secondSplit.get(0)).getSplitId(),
			"two splits must not share an identifier");

		int exitCode = run("share", "combine", "--share", firstSplit.get(0), "--share",
			secondSplit.get(1));

		assertEquals(1, exitCode);
		assertTrue(err.contains("different splits"),
			"the message must name the problem, but was: '" + err + "'");
	}

	@Test
	void theSameShareTwiceDoesNotCountTwice()
	{
		List<String> lines = splitLines(2, 3);

		int exitCode = run("share", "combine", "--share", lines.get(0), "--share", lines.get(0));

		assertEquals(1, exitCode);
		assertTrue(err.contains("more than once"),
			"the message must name the problem, but was: '" + err + "'");
	}

	@Test
	void aShareAlteredWhileBeingCopiedIsCaughtByItsOwnChecksum()
	{
		List<String> lines = splitLines(2, 3);
		String share = lines.get(0);
		// Change a character in the MIDDLE of the value field, as a typo while copying would.
		// Not the last one: in unpadded base64 only some bits of the final character are
		// significant, so 'A' and 'B' there can decode to identical bytes and the checksum, which
		// covers the decoded value, would legitimately still match. That is the same trap that
		// once made Argon2SupportTest flaky.
		int valueStart = share
			.indexOf(':',
				share.indexOf(':',
					share.indexOf(':', share.indexOf(':', share.indexOf(':') + 1) + 1) + 1) + 1)
			+ 1;
		int lastColon = share.lastIndexOf(':');
		int middle = valueStart + (lastColon - valueStart) / 2;
		char[] characters = share.toCharArray();
		characters[middle] = characters[middle] == 'A' ? 'B' : 'A';
		String mistyped = new String(characters);

		int exitCode = run("share", "combine", "--share", mistyped, "--share", lines.get(1));

		assertEquals(2, exitCode, "stderr was: '" + err + "'");
		assertTrue(err.contains("checksum"),
			"the message must point at the share itself, but was: '" + err + "'");
	}

	@Test
	void aLineThatIsNotAShareAtAllIsNamedAsSuch()
	{
		int exitCode = run("share", "combine", "--share", "just some text");

		assertEquals(2, exitCode);
		assertTrue(err.contains("not a mystic-crypt share"),
			"the message must say what a share looks like, but was: '" + err + "'");
	}

	@Test
	void sharesRoundTripThroughFiles(@TempDir File tempDir) throws IOException
	{
		File secretFile = new File(tempDir, "secret.bin");
		File sharesFile = new File(tempDir, "shares.txt");
		File recovered = new File(tempDir, "recovered.bin");
		byte[] secret = "file contents to be shared out".getBytes(StandardCharsets.UTF_8);
		Files.write(secretFile.toPath(), secret);

		assertEquals(0, run("share", "split", "--file", secretFile.getPath(), "-t", "2", "-n", "3",
			"-o", sharesFile.getPath()));
		assertTrue(err.contains("any 2 of them"),
			"the confirmation must state the threshold, but was: '" + err + "'");

		// keep only two of the three lines, the situation combine exists for
		List<String> all = Files.readAllLines(sharesFile.toPath());
		Files.write(sharesFile.toPath(), List.of(all.get(0), all.get(2)));

		assertEquals(0,
			run("share", "combine", "--file", sharesFile.getPath(), "-o", recovered.getPath()),
			"stderr was: '" + err + "'");
		assertArrayEquals(secret, Files.readAllBytes(recovered.toPath()));
	}

	@Test
	void theSecretCanComeThroughStandardInput()
	{
		assertEquals(0, runWithStdin("secret from standard input\n", "share", "split",
			"--secret-stdin", "-t", "2", "-n", "2"));
		List<String> lines = out.lines().filter(line -> !line.isBlank()).toList();

		assertEquals(0, run("share", "combine", "--share", lines.get(0), "--share", lines.get(1)));
		assertEquals("secret from standard input", out.trim());
	}

	@Test
	void aThresholdOfOneIsRefusedBecauseItIsNotASplit()
	{
		assertEquals(2, run("share", "split", "--secret", SECRET, "-t", "1", "-n", "3"));
		assertTrue(err.contains("at least 2"),
			"the message must say what is wrong, but was: '" + err + "'");
	}

	@Test
	void moreSharesThanTheSecretHasBytesIsRefusedWithTheLibraryReason()
	{
		assertEquals(2, run("share", "split", "--secret", "tiny", "-t", "2", "-n", "5"));
		assertTrue(err.contains("secret length"),
			"the message must explain the limit, but was: '" + err + "'");
	}

	@Test
	void fewerSharesThanTheThresholdCannotEvenBeSplit()
	{
		assertEquals(2, run("share", "split", "--secret", SECRET, "-t", "4", "-n", "2"));
		assertTrue(err.contains("at least the threshold"),
			"the message must explain the relation, but was: '" + err + "'");
	}

	@Test
	void missingInputIsNamedOnBothSides()
	{
		assertEquals(2, run("share", "split", "-t", "2", "-n", "3"));
		assertTrue(err.contains("--secret"), "stderr was: '" + err + "'");

		assertEquals(2, run("share", "combine"));
		assertTrue(err.contains("--share"), "stderr was: '" + err + "'");
	}

	@Test
	void blankLinesInASharesFileAreIgnoredRatherThanParsed(@TempDir File tempDir) throws IOException
	{
		File sharesFile = new File(tempDir, "shares.txt");
		List<String> lines = splitLines(2, 3);
		Files.write(sharesFile.toPath(), List.of(lines.get(0), "", "   ", lines.get(1)));

		assertEquals(0, run("share", "combine", "--file", sharesFile.getPath()),
			"stderr was: '" + err + "'");
		assertEquals(SECRET, out.trim());
	}

	@Test
	void anOutputPathThatCannotBeWrittenIsReportedAsAnError(@TempDir File tempDir)
	{
		List<String> lines = splitLines(2, 2);

		// a directory is not a file that can be written to, which is the plainest way to reach the
		// write failure without depending on file permissions
		int exitCode = run("share", "combine", "--share", lines.get(0), "--share", lines.get(1),
			"-o", tempDir.getPath());

		assertEquals(2, exitCode, "stderr was: '" + err + "'");
		assertFalse(err.isBlank(), "a failed write has to be explained, not only counted");
	}

	@Test
	void combiningIntoAFileConfirmsWhereTheSecretWent(@TempDir File tempDir) throws IOException
	{
		List<String> lines = splitLines(2, 2);
		File recovered = new File(tempDir, "secret.bin");

		assertEquals(0, run("share", "combine", "--share", lines.get(0), "--share", lines.get(1),
			"-o", recovered.getPath()), "stderr was: '" + err + "'");

		assertTrue(err.contains("wrote the reconstructed secret to " + recovered.getPath()),
			"stderr was: '" + err + "'");
		assertEquals(SECRET, Files.readString(recovered.toPath()));
	}

	@Test
	void combiningWithoutAFilePrintsTheSecretItself()
	{
		List<String> lines = splitLines(2, 2);

		assertEquals(0, run("share", "combine", "--share", lines.get(0), "--share", lines.get(1)));

		assertEquals(SECRET, out.trim(), "without -o the secret itself is the output");
	}

	@Test
	void everyShareCommandAnswersItsOwnHelp()
	{
		assertEquals(0, run("share", "--help"));
		assertTrue(out.contains("split") && out.contains("combine"));
		assertEquals(0, run("share", "split", "--help"));
		assertTrue(out.contains("--threshold"));
		assertEquals(0, run("share", "combine", "--help"));
		assertTrue(out.contains("--share"));
	}

	@Test
	void theBareShareCommandPrintsItsUsage()
	{
		assertEquals(0, run("share"));
		assertTrue(out.contains("split"), "stdout was: '" + out + "'");
	}
}
