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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.mystic.crypt.key.KeyExchangeSupport;

/**
 * Unit tests for the {@code keyx} subcommands, driven through the real command line as three
 * separate runs against real files, the way two people would use it.
 */
class KeyExchangeCommandTest extends AbstractCliTest
{

	private static final Pattern FINGERPRINT = Pattern
		.compile("shared secret fingerprint: ([0-9a-f]{8})");

	private static String fingerprintIn(String output)
	{
		Matcher matcher = FINGERPRINT.matcher(output);
		assertTrue(matcher.find(), "no fingerprint was printed in: '" + output + "'");
		return matcher.group(1);
	}

	@ParameterizedTest
	@ValueSource(strings = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "X25519",
			"Hybrid X25519 + ML-KEM-768" })
	void bothSidesArriveAtTheSameSecretInThreeSeparateRuns(String algorithm, @TempDir File tempDir)
		throws IOException
	{
		File privateKey = new File(tempDir, "recipient.key");
		File publicKey = new File(tempDir, "recipient.pub");
		File handshake = new File(tempDir, "handshake.txt");

		assertEquals(0, run("keyx", "new", "-a", algorithm, "-k", privateKey.getPath(), "-p",
			publicKey.getPath()), "stderr was: '" + err + "'");
		assertTrue(Files.readString(publicKey.toPath()).startsWith(KeyExchangeSupport.PREFIX),
			"the public half must be an envelope of this tool");

		assertEquals(0, run("keyx", "send", "-r", publicKey.getPath(), "-o", handshake.getPath()),
			"stderr was: '" + err + "'");
		String senderFingerprint = fingerprintIn(out);

		assertEquals(0,
			run("keyx", "receive", "-k", privateKey.getPath(), "-s", handshake.getPath()),
			"stderr was: '" + err + "'");
		String recipientFingerprint = fingerprintIn(out);

		assertEquals(senderFingerprint, recipientFingerprint,
			"both sides must derive the same secret for " + algorithm);
		assertTrue(out.contains("algorithm: " + algorithm),
			"the run must name the algorithm it used, but was: '" + out + "'");
	}

	@ParameterizedTest
	@ValueSource(strings = { "ML-KEM-768", "X25519", "Hybrid X25519 + ML-KEM-768" })
	void aMessageEncryptedWithTheSecretIsReadableOnTheOtherSide(String algorithm,
		@TempDir File tempDir)
	{
		File privateKey = new File(tempDir, "recipient.key");
		File publicKey = new File(tempDir, "recipient.pub");
		File handshake = new File(tempDir, "handshake.txt");
		File encrypted = new File(tempDir, "message.enc");

		assertEquals(0, run("keyx", "new", "-a", algorithm, "-k", privateKey.getPath(), "-p",
			publicKey.getPath()));
		assertEquals(0,
			run("keyx", "send", "-r", publicKey.getPath(), "-o", handshake.getPath(), "-m",
				"meet me at the usual place", "-e", encrypted.getPath()),
			"stderr was: '" + err + "'");

		assertEquals(0, run("keyx", "receive", "-k", privateKey.getPath(), "-s",
			handshake.getPath(), "-e", encrypted.getPath()), "stderr was: '" + err + "'");
		assertTrue(out.contains("message: meet me at the usual place"),
			"the message must come back readable, but the output was: '" + out + "'");
	}

	@Test
	void theHandshakeAndThePublicKeyAreNotTheSecret(@TempDir File tempDir) throws IOException
	{
		File privateKey = new File(tempDir, "recipient.key");
		File publicKey = new File(tempDir, "recipient.pub");
		File handshake = new File(tempDir, "handshake.txt");

		assertEquals(0, run("keyx", "new", "-k", privateKey.getPath(), "-p", publicKey.getPath()));
		assertEquals(0, run("keyx", "send", "-r", publicKey.getPath(), "-o", handshake.getPath()));
		String fingerprint = fingerprintIn(out);

		assertFalse(Files.readString(publicKey.toPath()).contains(fingerprint),
			"the public key must not carry the secret's fingerprint");
		assertFalse(Files.readString(handshake.toPath()).contains(fingerprint),
			"the handshake must not carry the secret's fingerprint");
	}

	@Test
	void theStoredPrivateKeyIsRecognisedAsTheSecretHalf(@TempDir File tempDir) throws IOException
	{
		File privateKey = new File(tempDir, "recipient.key");
		assertEquals(0, run("keyx", "new", "-k", privateKey.getPath()));

		assertTrue(out.contains("hand out only the public one"),
			"the run must say which file is the secret, but was: '" + out + "'");
		assertTrue(Files.readString(privateKey.toPath()).contains("$PRV$"),
			"the stored key must be marked as the private half");
		assertTrue(out.contains(KeyExchangeSupport.PREFIX),
			"without -p the public half is printed, but the output was: '" + out + "'");
	}

	/**
	 * The defect this pins: a public key has fewer parts than a private one, so a length check
	 * before the kind check reports "this is not a key of this tool" about a perfectly good public
	 * key and sends the user looking in the wrong place.
	 */
	@Test
	void handingThePublicHalfWhereThePrivateOneBelongsSaysExactlyThat(@TempDir File tempDir)
	{
		File privateKey = new File(tempDir, "recipient.key");
		File publicKey = new File(tempDir, "recipient.pub");
		File handshake = new File(tempDir, "handshake.txt");
		assertEquals(0, run("keyx", "new", "-k", privateKey.getPath(), "-p", publicKey.getPath()));
		assertEquals(0, run("keyx", "send", "-r", publicKey.getPath(), "-o", handshake.getPath()));

		int exitCode = run("keyx", "receive", "-k", publicKey.getPath(), "-s", handshake.getPath());

		assertEquals(2, exitCode);
		assertTrue(err.contains("public half"),
			"the message must name what was handed in, but was: '" + err + "'");
		assertFalse(err.contains("not a stored key of this tool"),
			"a good public key must not be called unrecognisable, but was: '" + err + "'");
	}

	@Test
	void aHandshakeOfAnotherAlgorithmIsRefusedByName(@TempDir File tempDir)
	{
		File mlKemKey = new File(tempDir, "mlkem.key");
		File x25519Key = new File(tempDir, "x25519.key");
		File x25519Public = new File(tempDir, "x25519.pub");
		File handshake = new File(tempDir, "handshake.txt");

		assertEquals(0, run("keyx", "new", "-a", "ML-KEM-768", "-k", mlKemKey.getPath()));
		assertEquals(0, run("keyx", "new", "-a", "X25519", "-k", x25519Key.getPath(), "-p",
			x25519Public.getPath()));
		assertEquals(0,
			run("keyx", "send", "-r", x25519Public.getPath(), "-o", handshake.getPath()));

		int exitCode = run("keyx", "receive", "-k", mlKemKey.getPath(), "-s", handshake.getPath());

		assertEquals(2, exitCode);
		assertTrue(err.contains("this handshake is for X25519"),
			"the message must name both sides, but was: '" + err + "'");
	}

	@Test
	void theWrongPrivateKeyDoesNotProduceTheSendersSecret(@TempDir File tempDir)
	{
		File rightKey = new File(tempDir, "right.key");
		File rightPublic = new File(tempDir, "right.pub");
		File wrongKey = new File(tempDir, "wrong.key");
		File handshake = new File(tempDir, "handshake.txt");
		File encrypted = new File(tempDir, "message.enc");

		assertEquals(0, run("keyx", "new", "-k", rightKey.getPath(), "-p", rightPublic.getPath()));
		assertEquals(0, run("keyx", "new", "-k", wrongKey.getPath()));
		assertEquals(0, run("keyx", "send", "-r", rightPublic.getPath(), "-o", handshake.getPath(),
			"-m", "for the right recipient", "-e", encrypted.getPath()));
		String senderFingerprint = fingerprintIn(out);

		int exitCode = run("keyx", "receive", "-k", wrongKey.getPath(), "-s", handshake.getPath(),
			"-e", encrypted.getPath());

		// ML-KEM decapsulates to *some* secret with any well formed private key, so the check that
		// matters is that it is not the sender's and the message stays unreadable
		assertFalse(out.contains("for the right recipient"),
			"the message must not be readable with the wrong key, but the output was: '" + out
				+ "'");
		if (exitCode == 0)
		{
			assertFalse(out.contains(senderFingerprint),
				"a different key must not arrive at the sender's secret");
		}
	}

	@Test
	void aFileThatIsNotFromThisToolIsNamedAsSuch(@TempDir File tempDir) throws IOException
	{
		File foreign = new File(tempDir, "foreign.txt");
		Files.writeString(foreign.toPath(), "just some text", StandardCharsets.UTF_8);

		assertEquals(2, run("keyx", "send", "-r", foreign.getPath()));
		assertTrue(err.contains("is not from this tool"), "stderr was: '" + err + "'");

		assertEquals(2, run("keyx", "receive", "-k", foreign.getPath(), "-s", foreign.getPath()));
		assertTrue(err.contains("not a stored key of this tool"), "stderr was: '" + err + "'");
	}

	@Test
	void anUnknownAlgorithmListsTheOnesThatExist(@TempDir File tempDir)
	{
		File key = new File(tempDir, "unused.key");

		assertEquals(2, run("keyx", "new", "-a", "ML-KEM-2048", "-k", key.getPath()));
		assertTrue(err.contains("is not one of") && err.contains("ML-KEM-768"),
			"the message must list the algorithms, but was: '" + err + "'");
	}

	@Test
	void anEmptyHandshakeFileSaysThereIsNothingToRead(@TempDir File tempDir) throws IOException
	{
		File key = new File(tempDir, "recipient.key");
		File empty = new File(tempDir, "empty.txt");
		assertEquals(0, run("keyx", "new", "-k", key.getPath()));
		Files.writeString(empty.toPath(), "   ", StandardCharsets.UTF_8);

		assertEquals(2, run("keyx", "receive", "-k", key.getPath(), "-s", empty.getPath()));
		assertTrue(err.contains("nothing to read"), "stderr was: '" + err + "'");
	}

	/**
	 * Each of the three runs prints what it did and where, and a run that wrote a file must say so
	 * rather than leaving the reader to check the filesystem.
	 */
	@Test
	void everyRunSaysWhatItWroteAndWhere(@TempDir File tempDir)
	{
		File privateKey = new File(tempDir, "recipient.key");
		File publicKey = new File(tempDir, "recipient.pub");
		File handshake = new File(tempDir, "handshake.txt");

		assertEquals(0, run("keyx", "new", "-k", privateKey.getPath(), "-p", publicKey.getPath()));
		assertTrue(out.contains("algorithm: " + KeyExchangeSupport.ML_KEM_768),
			"new must name the algorithm, but was: '" + out + "'");
		assertTrue(out.contains("private key written to " + privateKey.getPath()),
			"new must name the private key file, but was: '" + out + "'");
		assertTrue(out.contains("public key written to " + publicKey.getPath()),
			"new must name the public key file, but was: '" + out + "'");

		assertEquals(0, run("keyx", "send", "-r", publicKey.getPath(), "-o", handshake.getPath()));
		assertTrue(out.contains("algorithm: " + KeyExchangeSupport.ML_KEM_768),
			"send must name the algorithm, but was: '" + out + "'");
		assertTrue(out.contains("handshake written to " + handshake.getPath()),
			"send must name the handshake file, but was: '" + out + "'");

		assertEquals(0,
			run("keyx", "receive", "-k", privateKey.getPath(), "-s", handshake.getPath()));
		assertTrue(out.contains("algorithm: " + KeyExchangeSupport.ML_KEM_768),
			"receive must name the algorithm, but was: '" + out + "'");
	}

	@Test
	void anEncryptedMessageWrittenToAFileIsAnnouncedByName(@TempDir File tempDir)
	{
		File privateKey = new File(tempDir, "r.key");
		File publicKey = new File(tempDir, "r.pub");
		File handshake = new File(tempDir, "h.txt");
		File encrypted = new File(tempDir, "m.enc");
		assertEquals(0, run("keyx", "new", "-k", privateKey.getPath(), "-p", publicKey.getPath()));

		assertEquals(0, run("keyx", "send", "-r", publicKey.getPath(), "-o", handshake.getPath(),
			"-m", "hello", "-e", encrypted.getPath()));

		assertTrue(out.contains("encrypted message written to " + encrypted.getPath()),
			"stdout was: '" + out + "'");
	}

	@Test
	void everyKeyxCommandAnswersItsOwnHelp()
	{
		assertEquals(0, run("keyx", "--help"));
		assertTrue(out.contains("new") && out.contains("send") && out.contains("receive"));
		assertEquals(0, run("keyx", "new", "--help"));
		assertTrue(out.contains("--algorithm"));
		assertEquals(0, run("keyx", "send", "--help"));
		assertTrue(out.contains("--recipient"));
		assertEquals(0, run("keyx", "receive", "--help"));
		assertTrue(out.contains("--handshake"));
	}

	@Test
	void theBareKeyxCommandPrintsItsUsage()
	{
		assertEquals(0, run("keyx"));
		assertTrue(out.contains("send"), "stdout was: '" + out + "'");
	}

	@Test
	void theFingerprintIsShortEnoughToReadOutAndNotTheSecretItself(@TempDir File tempDir)
		throws Exception
	{
		File key = new File(tempDir, "recipient.key");
		File publicKey = new File(tempDir, "recipient.pub");
		assertEquals(0, run("keyx", "new", "-k", key.getPath(), "-p", publicKey.getPath()));
		assertEquals(0, run("keyx", "send", "-r", publicKey.getPath()));

		String fingerprint = fingerprintIn(out);
		assertEquals(8, fingerprint.length(), "eight hex characters can be read out loud");
		assertNotNull(fingerprint);
	}
}
