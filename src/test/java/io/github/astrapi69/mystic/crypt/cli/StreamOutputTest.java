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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests for issue #104: the commands whose output is a stream write it to standard output when the
 * output path is {@code -}, and everything that is a remark about the result goes to standard
 * error.
 * <p>
 * The separation is what makes a pipeline work. Standard output carries the result and nothing
 * else, so {@code | gpg}, {@code | base64 -d} or {@code > file} get exactly the bytes; the caller
 * still sees what happened, on the other stream.
 * <p>
 * {@code keygen}, {@code keyx new} and {@code sign} keep the refusal from #101: a private key or a
 * raw signature on standard output is its own surprise.
 */
class StreamOutputTest extends AbstractCliTest
{

	private File plainFile(final File tempDir) throws Exception
	{
		File plain = new File(tempDir, "plain.txt");
		Files.writeString(plain.toPath(), "the content under test");
		return plain;
	}

	/** Asserts that no file called '-' was left behind, whatever else happened. */
	private void assertNoDashFile()
	{
		File dash = new File("-");
		boolean existed = dash.exists();
		dash.delete();
		assertFalse(existed, "no file named '-' may be left in the working directory");
	}

	@Test
	void encryptWritesTheCipherTextToStandardOutput(@TempDir File tempDir) throws Exception
	{
		File plain = plainFile(tempDir);

		int exitCode = run("encrypt", "--in", plain.getAbsolutePath(), "--out", "-", "--passphrase",
			"secret");

		assertNoDashFile();
		assertEquals(0, exitCode, "encrypt must succeed, but stderr was: " + err);
		assertFalse(out.isBlank(), "the cipher text must be on standard output");
		assertFalse(out.contains("encrypted "),
			"standard output must carry the result alone, but was: " + out);
	}

	@Test
	void decryptWritesThePlainTextToStandardOutput(@TempDir File tempDir) throws Exception
	{
		File plain = plainFile(tempDir);
		File encrypted = new File(tempDir, "encrypted.bin");
		run("encrypt", "--in", plain.getAbsolutePath(), "--out", encrypted.getAbsolutePath(),
			"--passphrase", "secret");

		int exitCode = run("decrypt", "--in", encrypted.getAbsolutePath(), "--out", "-",
			"--passphrase", "secret");

		assertNoDashFile();
		assertEquals(0, exitCode, "decrypt must succeed, but stderr was: " + err);
		assertEquals("the content under test", out.strip(),
			"standard output must carry the plain text alone, but was: " + out);
	}

	@Test
	void convertWritesThePemToStandardOutput(@TempDir File tempDir) throws Exception
	{
		File pem = new File(tempDir, "key.pem");
		run("keygen", "--algorithm", "RSA", "--size", "2048", "--out-private",
			pem.getAbsolutePath());

		int exitCode = run("convert", "--in", pem.getAbsolutePath(), "--to", "pkcs8", "--out", "-");

		assertNoDashFile();
		assertEquals(0, exitCode, "convert must succeed, but stderr was: " + err);
		assertTrue(out.startsWith("-----BEGIN"),
			"standard output must start with the pem itself, but was: "
				+ out.lines().findFirst().orElse(""));
		assertFalse(out.contains(" is "),
			"the description belongs on standard error, but standard output was: " + out);
	}

	@Test
	void convertWithoutAnOutputPathAlsoPrintsThePemAlone(@TempDir File tempDir) throws Exception
	{
		File pem = new File(tempDir, "key.pem");
		run("keygen", "--algorithm", "RSA", "--size", "2048", "--out-private",
			pem.getAbsolutePath());

		run("convert", "--in", pem.getAbsolutePath(), "--to", "pkcs8");

		assertTrue(out.startsWith("-----BEGIN"),
			"leaving the option out must print the pem alone, but standard output was: "
				+ out.lines().findFirst().orElse(""));
	}

	@Test
	void shareSplitWritesTheSharesToStandardOutput() throws Exception
	{
		int exitCode = run("share", "split", "--secret", "the-secret", "-t", "2", "-n", "3", "-o",
			"-");

		assertNoDashFile();
		assertEquals(0, exitCode, "share split must succeed, but stderr was: " + err);
		assertEquals(3, out.strip().lines().count(),
			"standard output must carry the three share lines alone, but was: " + out);
	}

	@Test
	void shareCombineWritesTheSecretToStandardOutput(@TempDir File tempDir) throws Exception
	{
		File shares = new File(tempDir, "shares.txt");
		run("share", "split", "--secret", "the-secret", "-t", "2", "-n", "3", "-o",
			shares.getAbsolutePath());
		String[] lines = Files.readString(shares.toPath(), StandardCharsets.UTF_8).strip()
			.split("\\R");

		int exitCode = run("share", "combine", "--share", lines[0], "--share", lines[1], "-o", "-");

		assertNoDashFile();
		assertEquals(0, exitCode, "share combine must succeed, but stderr was: " + err);
		assertEquals("the-secret", out.strip(),
			"standard output must carry the secret alone, but was: " + out);
	}

	/**
	 * Writing to a file is the other half of the same rule: the remark about what was written is
	 * not the result either, so it goes to standard error there as well.
	 *
	 * @param tempDir
	 *            the directory the file is written into
	 * @throws Exception
	 *             if the run fails
	 */
	@Test
	void theRemarkAboutAWrittenFileIsOnStandardError(@TempDir File tempDir) throws Exception
	{
		File plain = plainFile(tempDir);
		File encrypted = new File(tempDir, "encrypted.bin");

		int exitCode = run("encrypt", "--in", plain.getAbsolutePath(), "--out",
			encrypted.getAbsolutePath(), "--passphrase", "secret");

		assertEquals(0, exitCode);
		assertTrue(err.contains("encrypted "),
			"the remark must be on standard error, but stderr was: " + err);
		assertTrue(out.isBlank(),
			"standard output must stay empty when the result went to a file, but was: " + out);
	}

	/**
	 * Der is binary, so there is nothing to print. The marker is accepted as far as being
	 * understood and then refused for what it would mean here, which is a different answer from the
	 * file named '-' it used to produce.
	 *
	 * @param tempDir
	 *            the directory the key is written into
	 * @throws Exception
	 *             if the key cannot be generated
	 */
	@Test
	void convertRefusesToPrintDerBecauseItIsBinary(@TempDir File tempDir) throws Exception
	{
		File pem = new File(tempDir, "key.pem");
		run("keygen", "--algorithm", "RSA", "--size", "2048", "--out-private",
			pem.getAbsolutePath());

		int exitCode = run("convert", "--in", pem.getAbsolutePath(), "--to", "der", "--out", "-");

		assertNoDashFile();
		assertNotEquals(0, exitCode, "der cannot be printed, so this must not succeed");
		assertTrue(err.contains("binary and cannot be printed"),
			"the message must say why, but stderr was: " + err);
	}

	@Test
	void keygenStillRefusesADashBecauseAPrivateKeyIsNotAStream()
	{
		assertNotEquals(0,
			run("keygen", "--algorithm", "RSA", "--size", "2048", "--out-private", "-"));
		assertNoDashFile();
		assertTrue(err.contains("--out-private"), "the message must name the option: " + err);
	}
}
