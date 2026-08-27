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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Regression tests for issue #101: an output option took {@code -} as a file name, so a file
 * literally called {@code -} appeared in the working directory while the caller believed the bytes
 * had gone to standard output.
 * <p>
 * The input side teaches that convention - {@code --in -} reads standard input - and standard
 * output is already reachable on the output side by leaving the option out, which is what the
 * commands that support it document. So {@code -} as an output path is not a missing feature but a
 * name that shadows a working one, and every command refuses it the way {@code sign} already did.
 */
class DashAsOutputPathTest extends AbstractCliTest
{

	/**
	 * Runs the given command line and asserts that it refused, said which option was at fault, and
	 * left no file behind.
	 *
	 * @param option
	 *            the option whose value was the dash, which the message has to name
	 * @param args
	 *            the command line to run
	 */
	private void assertTheDashIsRefused(final String option, final String... args)
	{
		File dashInTheWorkingDirectory = new File("-");
		dashInTheWorkingDirectory.delete();

		int exitCode = run(args);

		assertNotEquals(0, exitCode,
			option + " must not report success for a dash, but the output was: " + out);
		assertFalse(dashInTheWorkingDirectory.exists(),
			option + " must not leave a file named '-' in the working directory");
		assertTrue(String.valueOf(err).contains(option),
			"the message must name " + option + ", but was: " + err);
		dashInTheWorkingDirectory.delete();
	}

	@Test
	void encryptRefusesADashAsItsOutput(@TempDir File tempDir) throws Exception
	{
		File plain = new File(tempDir, "plain.txt");
		Files.writeString(plain.toPath(), "some content");

		assertTheDashIsRefused("--out", "encrypt", "--in", plain.getAbsolutePath(), "--out", "-",
			"--passphrase", "secret");
	}

	@Test
	void decryptRefusesADashAsItsOutput(@TempDir File tempDir) throws Exception
	{
		File plain = new File(tempDir, "plain.txt");
		Files.writeString(plain.toPath(), "some content");
		File encrypted = new File(tempDir, "encrypted.bin");
		run("encrypt", "--in", plain.getAbsolutePath(), "--out", encrypted.getAbsolutePath(),
			"--passphrase", "secret");

		assertTheDashIsRefused("--out", "decrypt", "--in", encrypted.getAbsolutePath(), "--out",
			"-", "--passphrase", "secret");
	}

	@Test
	void keygenRefusesADashForThePrivateKey()
	{
		assertTheDashIsRefused("--out-private", "keygen", "--algorithm", "RSA", "--size", "2048",
			"--out-private", "-");
	}

	@Test
	void keygenRefusesADashForThePublicKey()
	{
		assertTheDashIsRefused("--out-public", "keygen", "--algorithm", "RSA", "--size", "2048",
			"--out-public", "-");
	}

	@Test
	void convertRefusesADashAsItsOutput(@TempDir File tempDir) throws Exception
	{
		File pem = new File(tempDir, "key.pem");
		run("keygen", "--algorithm", "RSA", "--size", "2048", "--out-private",
			pem.getAbsolutePath());

		assertTheDashIsRefused("--out", "convert", "--in", pem.getAbsolutePath(), "--to", "der",
			"--out", "-");
	}

	@Test
	void shareSplitRefusesADashAsItsOutput()
	{
		assertTheDashIsRefused("--out", "share", "split", "--secret", "the-secret", "-t", "2", "-n",
			"3", "-o", "-");
	}

	@Test
	void keyExchangeRefusesADashForTheKeyItWrites()
	{
		assertTheDashIsRefused("--key", "keyx", "new", "-a", "X25519", "-k", "-");
	}

	/**
	 * The guard is the first statement of every {@code call()}, so it answers before the command
	 * looks at anything else. These four options are therefore driven with arguments that would not
	 * carry the command through on their own - what is asserted is the refusal, and that it comes
	 * first.
	 */
	@Test
	void shareCombineRefusesADashAsItsOutput()
	{
		assertTheDashIsRefused("--out", "share", "combine", "--share", "1-aa", "--share", "2-bb",
			"-o", "-");
	}

	@Test
	void keyExchangeSendRefusesADashForTheHandshake()
	{
		assertTheDashIsRefused("--out", "keyx", "send", "-r", "no-such-file", "-o", "-");
	}

	@Test
	void keyExchangeSendRefusesADashForTheEncryptedMessage()
	{
		assertTheDashIsRefused("--encrypted", "keyx", "send", "-r", "no-such-file", "-e", "-");
	}

	@Test
	void keyExchangeReceiveRefusesADashForTheEncryptedMessage()
	{
		assertTheDashIsRefused("--encrypted", "keyx", "receive", "-k", "no-such-file", "-s",
			"no-such-file", "-e", "-");
	}

	/**
	 * The command that already refused, kept here so the parity is asserted and not assumed: every
	 * output option answers the same way.
	 *
	 * @param tempDir
	 *            the directory the key is written into
	 * @throws Exception
	 *             if the key cannot be generated
	 */
	@Test
	void signStillRefusesADashForTheSignature(@TempDir File tempDir) throws Exception
	{
		File pem = new File(tempDir, "key.pem");
		File data = new File(tempDir, "data.txt");
		Files.writeString(data.toPath(), "sign me");
		run("keygen", "--algorithm", "RSA", "--size", "2048", "--out-private",
			pem.getAbsolutePath());

		assertTheDashIsRefused("--signature", "sign", "--algorithm", "SHA256withRSA", "--key",
			pem.getAbsolutePath(), "--in", data.getAbsolutePath(), "--signature", "-");
	}
}
