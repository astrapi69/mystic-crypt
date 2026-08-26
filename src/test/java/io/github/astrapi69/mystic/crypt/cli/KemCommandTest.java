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
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HexFormat;
import java.util.stream.Stream;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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

	/**
	 * Pins that the exit code of {@code kem} is wired to the verdict of {@link KemCommand#report},
	 * not hard-coded: a shared-secret mismatch must surface as exit code 1 through the real CLI
	 * entry point. With a well-behaved provider, ML-KEM correctness makes the mismatch branch
	 * unreachable from {@link KemCommand#call()}, so this test registers a deliberately
	 * inconsistent {@code ML-KEM-768} KEM provider at highest precedence whose decapsulator never
	 * returns the secret its encapsulator produced - the defective-provider scenario the exit-code
	 * contract exists for. A mutant that replaces {@code return report(...)} with {@code return 0}
	 * still prints the mismatch verdict (the call itself is not removed) but reports success to the
	 * shell, which this test rejects.
	 */
	@org.junit.jupiter.api.Test
	void kemProviderWhoseDecapsulationDisagreesSurfacesAsExitCodeOne()
	{
		Security.insertProviderAt(new MismatchedKemProvider(), 1);
		try
		{
			int exitCode = run("kem", "--algorithm", "ML-KEM-768");
			assertTrue(out.contains("shared secrets do not match"),
				"the mismatch verdict must be printed, but output was: '" + out + "'");
			assertEquals(1, exitCode,
				"a shared-secret mismatch must surface as exit code 1, not as success");
		}
		finally
		{
			Security.removeProvider(MismatchedKemProvider.NAME);
		}
	}

	/**
	 * A test-only security provider serving an intentionally defective {@code ML-KEM-768} KEM: its
	 * decapsulator never returns the secret its encapsulator produced. Registered at highest
	 * precedence it hijacks the provider-independent {@code KEM.getInstance("ML-KEM-768")} lookup
	 * inside {@link KemCommand#call()}, making the otherwise unreachable mismatch verdict of
	 * {@link KemCommand#report} observable through the CLI.
	 */
	static final class MismatchedKemProvider extends Provider
	{

		@java.io.Serial
		private static final long serialVersionUID = 1L;

		/** the provider name, used for registration and removal */
		static final String NAME = "MismatchedKemTestProvider";

		MismatchedKemProvider()
		{
			super(NAME, "1.0",
				"test-only ML-KEM-768 whose decapsulation disagrees " + "with its encapsulation");
			putService(
				new Service(this, "KEM", "ML-KEM-768", MismatchedKemSpi.class.getName(), null, null)
				{
					@Override
					public Object newInstance(Object constructorParameter)
					{
						return new MismatchedKemSpi();
					}
				});
		}
	}

	/**
	 * The {@link KEMSpi} of {@link MismatchedKemProvider}: encapsulation yields one constant
	 * secret, decapsulation a different one, so the two parties of the exchange never agree.
	 */
	static final class MismatchedKemSpi implements KEMSpi
	{

		/** the shared secret the sender derives */
		private static final byte[] SENDER_SECRET = HexFormat.of().parseHex("11".repeat(32));

		/** the differing shared secret the recipient derives */
		private static final byte[] RECIPIENT_SECRET = HexFormat.of().parseHex("22".repeat(32));

		/** the constant ciphertext this fake KEM produces */
		private static final byte[] CIPHERTEXT = HexFormat.of().parseHex("c1c2c3c4c5c6c7c8");

		@Override
		public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey,
			AlgorithmParameterSpec spec, SecureRandom secureRandom)
		{
			return new EncapsulatorSpi()
			{
				@Override
				public KEM.Encapsulated engineEncapsulate(int from, int to, String keyAlgorithm)
				{
					return new KEM.Encapsulated(
						new SecretKeySpec(SENDER_SECRET, from, to - from, keyAlgorithm),
						CIPHERTEXT.clone(), null);
				}

				@Override
				public int engineSecretSize()
				{
					return SENDER_SECRET.length;
				}

				@Override
				public int engineEncapsulationSize()
				{
					return CIPHERTEXT.length;
				}
			};
		}

		@Override
		public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey,
			AlgorithmParameterSpec spec)
		{
			return new DecapsulatorSpi()
			{
				@Override
				public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to,
					String keyAlgorithm)
				{
					return new SecretKeySpec(RECIPIENT_SECRET, from, to - from, keyAlgorithm);
				}

				@Override
				public int engineSecretSize()
				{
					return RECIPIENT_SECRET.length;
				}

				@Override
				public int engineEncapsulationSize()
				{
					return CIPHERTEXT.length;
				}
			};
		}
	}

}
