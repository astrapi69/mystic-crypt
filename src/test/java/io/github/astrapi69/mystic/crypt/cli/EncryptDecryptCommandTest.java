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
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.astrapi69.mystic.crypt.pw.PassphraseCryptor;

/**
 * Unit tests for the {@code encrypt} and {@code decrypt} subcommands, driven through the real
 * command line against real files.
 */
class EncryptDecryptCommandTest extends AbstractCliTest
{

	@Test
	void aFileSurvivesTheRoundTripByteForByte(@TempDir File tempDir) throws IOException
	{
		File plain = new File(tempDir, "plain.txt");
		File encrypted = new File(tempDir, "plain.enc");
		File back = new File(tempDir, "back.txt");
		byte[] original = "the contents of a file\nwith two lines\n"
			.getBytes(StandardCharsets.UTF_8);
		Files.write(plain.toPath(), original);

		assertEquals(0, run("encrypt", "-i", plain.getPath(), "-o", encrypted.getPath(), "-p",
			"a good passphrase"));
		assertTrue(PassphraseCryptor.isEncrypted(Files.readAllBytes(encrypted.toPath())),
			"the written file must carry the format marker");
		assertFalse(new String(Files.readAllBytes(encrypted.toPath()), StandardCharsets.UTF_8)
			.contains("with two lines"), "the plaintext must not survive in the output");

		assertEquals(0, run("decrypt", "-i", encrypted.getPath(), "-o", back.getPath(), "-p",
			"a good passphrase"));
		assertArrayEquals(original, Files.readAllBytes(back.toPath()));
	}

	@Test
	void textIsPrintedAsBase64AndComesBackAsTheSameText()
	{
		assertEquals(0, run("encrypt", "--text", "hello over the wire", "-p", "pass"));
		String base64 = out.trim();
		assertTrue(PassphraseCryptor.isEncrypted(Base64.getDecoder().decode(base64)),
			"the printed text must be the base64 of an encrypted blob, but was: '" + base64 + "'");

		assertEquals(0, run("decrypt", "--text", base64, "-p", "pass"));
		assertEquals("hello over the wire", out.trim());
	}

	@Test
	void theTextAndThePassphraseCanBothComeThroughStandardInput()
	{
		assertEquals(0, runWithStdin("from stdin\n", "encrypt", "--text-stdin", "-p", "pass"));
		String base64 = out.trim();

		assertEquals(0, runWithStdin("pass\n", "decrypt", "--text", base64, "--passphrase-stdin"));
		assertEquals("from stdin", out.trim());
	}

	@Test
	void aWrongPassphraseIsTheNegativeAnswerAndExitsWithOne(@TempDir File tempDir)
		throws IOException
	{
		File plain = new File(tempDir, "plain.txt");
		File encrypted = new File(tempDir, "plain.enc");
		Files.writeString(plain.toPath(), "secret");
		assertEquals(0,
			run("encrypt", "-i", plain.getPath(), "-o", encrypted.getPath(), "-p", "right"));

		int exitCode = run("decrypt", "-i", encrypted.getPath(), "-p", "wrong");

		assertEquals(1, exitCode,
			"a wrong passphrase is the negative answer, not a tool error, but exit code was "
				+ exitCode + " and stderr was: '" + err + "'");
		assertFalse(out.contains("secret"), "nothing of the plaintext may be printed");
		assertFalse(err.isBlank(), "the failure must be explained on stderr");
	}

	@Test
	void alteredCiphertextIsRejectedRatherThanDecryptedIntoRubbish(@TempDir File tempDir)
		throws IOException
	{
		File plain = new File(tempDir, "plain.txt");
		File encrypted = new File(tempDir, "plain.enc");
		Files.writeString(plain.toPath(), "do not tamper");
		assertEquals(0,
			run("encrypt", "-i", plain.getPath(), "-o", encrypted.getPath(), "-p", "pass"));

		byte[] tampered = Files.readAllBytes(encrypted.toPath());
		tampered[tampered.length - 1] ^= 0x01;
		Files.write(encrypted.toPath(), tampered);

		assertEquals(1, run("decrypt", "-i", encrypted.getPath(), "-p", "pass"));
	}

	@Test
	void aFileThatIsNotEncryptedAtAllIsAToolErrorNotANegativeAnswer(@TempDir File tempDir)
		throws IOException
	{
		File plain = new File(tempDir, "not-encrypted.txt");
		Files.writeString(plain.toPath(), "just a text file");

		int exitCode = run("decrypt", "-i", plain.getPath(), "-p", "pass");

		assertEquals(2, exitCode,
			"an input of the wrong kind is an error, stderr was: '" + err + "'");
		assertTrue(err.contains("marker"),
			"the message must say what was expected, but was: '" + err + "'");
	}

	@Test
	void bothStandardInputOptionsTogetherAreRefusedWithAnExplanation()
	{
		int exitCode = runWithStdin("something\n", "encrypt", "--text-stdin", "--passphrase-stdin");

		assertEquals(2, exitCode);
		assertTrue(err.contains("--text-stdin") && err.contains("--passphrase-stdin"),
			"the message must name both options, but was: '" + err + "'");
	}

	@Test
	void encryptingTheSameFileTwiceProducesDifferentOutput(@TempDir File tempDir) throws IOException
	{
		File plain = new File(tempDir, "plain.txt");
		File first = new File(tempDir, "first.enc");
		File second = new File(tempDir, "second.enc");
		Files.writeString(plain.toPath(), "same input");

		assertEquals(0, run("encrypt", "-i", plain.getPath(), "-o", first.getPath(), "-p", "pass"));
		assertEquals(0,
			run("encrypt", "-i", plain.getPath(), "-o", second.getPath(), "-p", "pass"));

		assertNotEquals(Base64.getEncoder().encodeToString(Files.readAllBytes(first.toPath())),
			Base64.getEncoder().encodeToString(Files.readAllBytes(second.toPath())),
			"a fresh salt and nonce per run must make the two outputs differ");
	}

	@Test
	void aMissingPassphraseSaysWhichOptionsProvideIt()
	{
		assertEquals(2, run("encrypt", "--text", "no passphrase given"));
		assertTrue(err.contains("--passphrase"),
			"the message must name the option, but was: '" + err + "'");
	}

	@Test
	void textToDecryptThatIsNotBase64SaysSoRatherThanFailingOnTheFormatCheck()
	{
		int exitCode = run("decrypt", "--text", "this is certainly not base64 ***", "-p", "pass");

		assertEquals(2, exitCode);
		assertTrue(err.contains("base64"),
			"the message must name what the text was expected to be, but was: '" + err + "'");
	}

	@Test
	void decryptAlsoRefusesTwoReadersOfStandardInput()
	{
		int exitCode = runWithStdin("something\n", "decrypt", "--text-stdin", "--passphrase-stdin");

		assertEquals(2, exitCode);
		assertTrue(err.contains("--text-stdin"),
			"the message must name the options, but was: '" + err + "'");
	}

	/**
	 * Writing to a file prints a confirmation instead of the content, and it has to name both how
	 * much was written and where, otherwise a run that wrote nothing looks the same as one that
	 * worked.
	 */
	@Test
	void writingToAFileConfirmsHowMuchWentWhere(@TempDir File tempDir) throws IOException
	{
		File plain = new File(tempDir, "plain.txt");
		File encrypted = new File(tempDir, "plain.enc");
		File back = new File(tempDir, "back.txt");
		Files.writeString(plain.toPath(), "0123456789");

		assertEquals(0,
			run("encrypt", "-i", plain.getPath(), "-o", encrypted.getPath(), "-p", "pass"));
		assertTrue(out.contains("encrypted 10 bytes to " + encrypted.getPath()),
			"stdout was: '" + out + "'");

		assertEquals(0,
			run("decrypt", "-i", encrypted.getPath(), "-o", back.getPath(), "-p", "pass"));
		assertTrue(out.contains("decrypted 10 bytes to " + back.getPath()),
			"stdout was: '" + out + "'");
	}

	@Test
	void bothCommandsAnswerTheirOwnHelp()
	{
		assertEquals(0, run("encrypt", "--help"));
		assertTrue(out.contains("--passphrase-stdin"));
		assertEquals(0, run("decrypt", "--help"));
		assertTrue(out.contains("--passphrase-stdin"));
	}
}
