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

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for the {@code kem} subcommand.
 */
class KemCommandTest extends AbstractCliTest
{

	@ParameterizedTest
	@ValueSource(strings = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "hybrid" })
	void bothPartiesDeriveMatchingSecrets(String algorithm)
	{
		assertEquals(0, run("kem", "--algorithm", algorithm));
		assertTrue(out.contains("shared secrets match"),
			algorithm + " sender and recipient must derive the same secret");
		assertTrue(out.contains("ciphertext:"), "must print the ciphertext");
		assertTrue(out.contains("sender-secret:") && out.contains("recipient-secret:"));
		// the report must echo which algorithm produced the exchange, verbatim as given
		assertTrue(out.contains("algorithm: " + algorithm),
			"the report must name the algorithm it ran with, but was: '" + out + "'");
	}

	/**
	 * One {@link KemCommand#report} case: the two secrets to compare together with the exit code
	 * and the verdict line they must produce, plus the verdict that must not appear.
	 */
	record ReportCase(String algorithm, byte[] ciphertext, byte[] senderSecret,
		byte[] recipientSecret, int expectedExitCode, String expectedVerdict,
		String forbiddenVerdict) {
	}

	static Stream<ReportCase> reportCases()
	{
		return Stream.of(
			new ReportCase("ML-KEM-768", new byte[] { 0x0a, 0x1b }, new byte[] { 0x2c, 0x3d },
				new byte[] { 0x2c, 0x3d }, 0, "shared secrets match",
				"shared secrets do not match"),
			new ReportCase("hybrid", new byte[] { (byte)0xfe }, new byte[] { 0x01 },
				new byte[] { 0x02 }, 1, "shared secrets do not match", "shared secrets match"));
	}

	/**
	 * Guards the complete printed contract of {@link KemCommand#report}: every one of the four
	 * labelled lines - algorithm, ciphertext, sender secret, recipient secret - plus the verdict
	 * line and the exit code derived from it. The {@code algorithm:} line is what tells the user
	 * which parameter set the printed ciphertext and secrets belong to, so this test fails if any
	 * of those {@code println} calls is dropped or the wrong value is formatted.
	 */
	@ParameterizedTest
	@MethodSource("reportCases")
	void reportPrintsEveryLabelledLineAndTheVerdict(ReportCase testCase)
	{
		HexFormat hex = HexFormat.of();
		PrintStream originalOut = System.out;
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		System.setOut(new PrintStream(buffer, true, StandardCharsets.UTF_8));
		int exitCode;
		try
		{
			exitCode = KemCommand.report(testCase.algorithm(), testCase.ciphertext(),
				testCase.senderSecret(), testCase.recipientSecret());
		}
		finally
		{
			System.setOut(originalOut);
		}
		String printed = buffer.toString(StandardCharsets.UTF_8);

		assertEquals(testCase.expectedExitCode(), exitCode,
			"the exit code must follow the comparison of the two secrets");
		assertTrue(printed.contains("algorithm: " + testCase.algorithm()),
			"the algorithm line is missing from: '" + printed + "'");
		assertTrue(printed.contains("ciphertext: " + hex.formatHex(testCase.ciphertext())),
			"the ciphertext line is missing from: '" + printed + "'");
		assertTrue(printed.contains("sender-secret: " + hex.formatHex(testCase.senderSecret())),
			"the sender-secret line is missing from: '" + printed + "'");
		assertTrue(
			printed.contains("recipient-secret: " + hex.formatHex(testCase.recipientSecret())),
			"the recipient-secret line is missing from: '" + printed + "'");
		assertTrue(printed.contains(testCase.expectedVerdict()),
			"the verdict line is missing from: '" + printed + "'");
		// the matching negative: only one of the two verdicts may ever be printed
		assertFalse(printed.contains(testCase.forbiddenVerdict()),
			"the opposite verdict must not be printed as well");
	}

	@org.junit.jupiter.api.Test
	void hybridIsCaseInsensitive()
	{
		assertEquals(0, run("kem", "--algorithm", "HYBRID"));
		assertTrue(out.contains("shared secrets match"));
	}

	@org.junit.jupiter.api.Test
	void unknownAlgorithmFails()
	{
		assertNotEquals(0, run("kem", "--algorithm", "ML-KEM-999"));
	}

	@org.junit.jupiter.api.Test
	void reportReturnsOneAndReportsNoMatchForDifferingSecrets()
	{
		java.io.PrintStream originalOut = System.out;
		java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
		System
			.setOut(new java.io.PrintStream(buffer, true, java.nio.charset.StandardCharsets.UTF_8));
		int exitCode;
		try
		{
			exitCode = KemCommand.report("test", new byte[] { 9 }, new byte[] { 1 },
				new byte[] { 2 });
		}
		finally
		{
			System.setOut(originalOut);
		}
		assertEquals(1, exitCode, "differing secrets must return exit code 1");
		assertTrue(buffer.toString(java.nio.charset.StandardCharsets.UTF_8)
			.contains("shared secrets do not match"));
	}
}
