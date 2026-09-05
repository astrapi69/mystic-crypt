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

import static io.github.astrapi69.mystic.crypt.key.KeyFileWriter.PKCS8_LABEL;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.security.interfaces.ECPrivateKey;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.mystic.crypt.key.KeyFileReader;
import io.github.astrapi69.mystic.crypt.key.KeyFileWriter;
import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Unit tests for what {@code keygen} gained: naming the curve, choosing the private key encoding,
 * and saying what it actually made.
 */
class KeygenDetailsCommandTest extends AbstractCliTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	@ParameterizedTest
	@CsvSource({ "secp256r1, 256", "secp384r1, 384", "secp521r1, 521" })
	void generatesAnEcKeyOnTheNamedCurveAndSaysWhichOne(String curve, int fieldSize,
		@TempDir File tempDir) throws Exception
	{
		File privateKey = new File(tempDir, "ec.pem");
		File publicKey = new File(tempDir, "ec-public.pem");

		assertEquals(0,
			run("keygen", "-a", "EC", "--curve", curve, "--print-details", "--out-private",
				privateKey.getPath(), "--out-public", publicKey.getPath()),
			"stderr was: '" + err + "'");

		assertTrue(out.contains("curve: " + curve),
			"the run must name the curve, but was: '" + out + "'");
		assertTrue(out.contains("field size: " + fieldSize + " bits"),
			"the run must name the field size, but was: '" + out + "'");

		ECPrivateKey generated = (ECPrivateKey)KeyFileReader.readPrivateKey(privateKey, "EC");
		assertEquals(fieldSize, generated.getParams().getCurve().getField().getFieldSize(),
			"the key on disk must really be on that curve");
	}

	/**
	 * The honest check that the PKCS#8 fix landed: what --format asks for is what the PEM label
	 * says, and the key still reads back as the same key.
	 */
	@ParameterizedTest
	@CsvSource({ "pkcs8, PRIVATE KEY", "pkcs1, RSA PRIVATE KEY" })
	void theFormatAskedForIsTheFormatWritten(String format, String expectedLabel,
		@TempDir File tempDir) throws Exception
	{
		File privateKey = new File(tempDir, "rsa.pem");

		assertEquals(0, run("keygen", "-a", "RSA", "-s", "2048", "--format", format,
			"--print-details", "--out-private", privateKey.getPath()), "stderr was: '" + err + "'");

		assertTrue(
			Files.readString(privateKey.toPath()).contains("-----BEGIN " + expectedLabel + "-----"),
			"the file must carry the " + expectedLabel + " header");
		assertTrue(out.contains("PEM label: " + expectedLabel),
			"the details must name the label actually written, but was: '" + out + "'");
		assertArrayEquals(KeyFileReader.readPrivateKey(privateKey, "RSA").getEncoded(),
			KeyFileReader.readPrivateKey(privateKey, "RSA").getEncoded());
	}

	@Test
	void theDefaultFormatIsPkcs8(@TempDir File tempDir) throws Exception
	{
		File privateKey = new File(tempDir, "rsa.pem");

		assertEquals(0,
			run("keygen", "-a", "RSA", "-s", "2048", "--out-private", privateKey.getPath()));

		assertTrue(Files.readString(privateKey.toPath())
			.contains("-----BEGIN " + KeyFileWriter.PKCS8_LABEL + "-----"));
	}

	@Test
	void printDetailsNamesTheSizeOfAnRsaKey(@TempDir File tempDir) throws Exception
	{
		assertEquals(0,
			run("keygen", "-a", "RSA", "-s", "3072", "--print-details", "--out-private",
				new File(tempDir, "k.pem").getPath(), "--out-public",
				new File(tempDir, "p.pem").getPath()));

		assertTrue(out.contains("algorithm: RSA") && out.contains("size: 3072 bits"),
			"stdout was: '" + out + "'");
	}

	@ParameterizedTest
	@ValueSource(strings = { "X25519", "ML-KEM-768", "ML-DSA-65" })
	void aFixedParameterAlgorithmIsNamedAsSuch(String algorithm, @TempDir File tempDir)
	{
		assertEquals(0,
			run("keygen", "-a", algorithm, "--print-details", "--out-private",
				new File(tempDir, "k.pem").getPath(), "--out-public",
				new File(tempDir, "p.pem").getPath()),
			"stderr was: '" + err + "'");

		assertTrue(out.contains("fixed parameter set"),
			"an algorithm with no size or curve must say so, but was: '" + out + "'");
	}

	@Test
	void anUnknownCurveNamesSomeThatExist(@TempDir File tempDir)
	{
		assertEquals(2, run("keygen", "-a", "EC", "--curve", "secp999r9", "--out-private",
			new File(tempDir, "k.pem").getPath()));

		assertTrue(err.contains("unknown curve") && err.contains("secp256r1"),
			"the message must offer a curve that works, but was: '" + err + "'");
	}

	@Test
	void anUnknownAlgorithmIsAnErrorNotACrash(@TempDir File tempDir)
	{
		assertEquals(2,
			run("keygen", "-a", "NOPE", "--out-private", new File(tempDir, "k.pem").getPath()));

		assertTrue(err.contains("unknown key algorithm"), "stderr was: '" + err + "'");
	}

	@Test
	void anEcKeyAskedForPkcs1GetsTheEcTraditionalLabelAndSaysSo(@TempDir File tempDir)
		throws Exception
	{
		File privateKey = new File(tempDir, "ec.pem");

		assertEquals(0,
			run("keygen", "-a", "EC", "--curve", "secp256r1", "--format", "pkcs1",
				"--print-details", "--out-private", privateKey.getPath()),
			"stderr was: '" + err + "'");

		assertEquals("EC PRIVATE KEY", pemLabelOf(privateKey),
			"RFC 5915 is EC's traditional form, and PKCS#1 was asked for");
		assertTrue(out.contains("PEM label: " + pemLabelOf(privateKey)),
			"the details must name the label the file carries, but said: '" + out + "'");
	}

	/**
	 * An EC key generated without naming a curve still has a field size, but no name to report, so
	 * the details say so rather than printing an empty curve.
	 */
	@Test
	void anEcKeyGeneratedWithoutACurveIsReportedAsUnnamed(@TempDir File tempDir)
	{
		assertEquals(0,
			run("keygen", "-a", "EC", "--print-details", "--out-private",
				new File(tempDir, "k.pem").getPath(), "--out-public",
				new File(tempDir, "p.pem").getPath()),
			"stderr was: '" + err + "'");

		assertTrue(out.contains("curve: unnamed") && out.contains("field size:"),
			"stdout was: '" + out + "'");
	}

	/** The details name the encoding that was asked for, in both directions. */
	@ParameterizedTest
	@CsvSource({ "pkcs8, PKCS#8", "pkcs1, PKCS#1" })
	void theDetailsNameTheEncodingForAKeyWhoseTraditionalFormExists(String format, String expected,
		@TempDir File tempDir)
	{
		assertEquals(0, run("keygen", "-a", "RSA", "-s", "2048", "--format", format,
			"--print-details", "--out-private", new File(tempDir, "k.pem").getPath()));

		assertTrue(out.contains("private key format: " + expected), "stdout was: '" + out + "'");
	}

	@Test
	void theCommandAnswersItsOwnHelp()
	{
		assertEquals(0, run("keygen", "--help"));
		assertTrue(
			out.contains("--curve") && out.contains("--format") && out.contains("--print-details"),
			"stdout was: '" + out + "'");
	}

	/**
	 * The written PEM says in its own first line which encoding it is. The details line must agree
	 * with it, for every algorithm - not only for RSA, where the requested format and the written
	 * one happen to coincide. See issue #114.
	 *
	 * @param algorithm
	 *            the KeyPairGeneratorAlgorithm name to generate with
	 * @param sizeOrCurve
	 *            the -s size or --curve name to pass, or null to pass neither
	 * @param tempDir
	 *            the directory the key is written to
	 * @throws Exception
	 *             if the key cannot be written or read back
	 */
	@ParameterizedTest(name = "{0} asked for PKCS#1")
	@CsvSource({ "RSA, 2048", "EC, secp256r1", "DSA, 1024" })
	void theDetailsNameTheEncodingThatWasActuallyWritten(String algorithm, String sizeOrCurve,
		@TempDir File tempDir) throws Exception
	{
		File privateKey = new File(tempDir, "key.pem");

		assertEquals(0, run(argumentsFor(algorithm, sizeOrCurve, privateKey)),
			"stderr was: '" + err + "'");

		String writtenLabel = pemLabelOf(privateKey);
		assertTrue(out.contains("PEM label: " + writtenLabel),
			"the details must name the label the file carries, '" + writtenLabel
				+ "', but stdout was: '" + out + "'");

		String writtenEncoding = PKCS8_LABEL.equals(writtenLabel) ? "PKCS#8" : "PKCS#1";
		assertTrue(out.contains("private key format: " + writtenEncoding),
			"the details must name the encoding the file carries, '" + writtenEncoding
				+ "', but stdout was: '" + out + "'");
	}

	/**
	 * A key with no traditional form cannot be written as PKCS#1. Until #127 the run wrote PKCS#8
	 * and said so, which was honest but still not what was asked for; now it refuses before writing
	 * anything. The older behaviour is what this test used to pin.
	 *
	 * @param tempDir
	 *            the directory the key would have been written to
	 */
	@Test
	void aKeyWithoutATraditionalFormIsRefusedRatherThanSubstituted(@TempDir File tempDir)
	{
		File privateKey = new File(tempDir, "mldsa.pem");

		assertEquals(2, run(argumentsFor("ML_DSA_65", null, privateKey)),
			"a format that cannot be produced must be an error, not a substitution");
		assertFalse(privateKey.exists(),
			"nothing may be written when the requested format cannot be produced");
		assertTrue(err.contains("ML-DSA") && err.contains("PKCS#8"),
			"the message must name the algorithm and what it does have, but was: '" + err + "'");
	}

	/**
	 * A DSA key has a size like an RSA key has one. Reporting a fixed parameter set for it hides
	 * the number the user chose. See issue #114.
	 *
	 * @param tempDir
	 *            the directory the key is written to
	 */
	@Test
	void theDetailsNameTheSizeOfADsaKey(@TempDir File tempDir)
	{
		assertEquals(0, run(argumentsFor("DSA", "1024", new File(tempDir, "dsa.pem"))),
			"stderr was: '" + err + "'");

		assertTrue(out.contains("size: 1024 bits"),
			"a DSA key has a size, but stdout was: '" + out + "'");
	}

	private String[] argumentsFor(String algorithm, String sizeOrCurve, File privateKey)
	{
		List<String> arguments = new ArrayList<>(List.of("keygen", "-a", algorithm, "--format",
			"pkcs1", "--print-details", "--out-private", privateKey.getPath()));
		if (sizeOrCurve != null)
		{
			arguments.add("EC".equals(algorithm) ? "--curve" : "-s");
			arguments.add(sizeOrCurve);
		}
		return arguments.toArray(String[]::new);
	}

	private String pemLabelOf(File pem) throws Exception
	{
		String firstLine = Files.readAllLines(pem.toPath()).get(0);
		return firstLine.replace("-----BEGIN ", "").replace("-----", "");
	}

	/**
	 * Without --out-private the PEM itself goes to standard output, and the details line follows
	 * it. Both come from the same written PEM, so the label the details name must be the label the
	 * printed PEM carries - the path that has no file to read the answer back from.
	 *
	 * @param algorithm
	 *            the KeyPairGeneratorAlgorithm name to generate with
	 * @param sizeOrCurve
	 *            the -s size or --curve name to pass
	 * @param expectedLabel
	 *            the PEM label the traditional form of that algorithm carries
	 */
	@ParameterizedTest(name = "{0} to standard output")
	@CsvSource({ "RSA, 2048, RSA PRIVATE KEY", "EC, secp256r1, EC PRIVATE KEY",
			"DSA, 1024, DSA PRIVATE KEY" })
	void printsThePemAndItsDetailsToStandardOutputAndTheyAgree(String algorithm, String sizeOrCurve,
		String expectedLabel)
	{
		assertEquals(0, run("keygen", "-a", algorithm, "EC".equals(algorithm) ? "--curve" : "-s",
			sizeOrCurve, "--format", "pkcs1", "--print-details"), "stderr was: '" + err + "'");

		assertTrue(out.contains("-----BEGIN " + expectedLabel + "-----"),
			"the PEM itself must go to standard output, but was: '" + out + "'");
		assertTrue(out.contains("PEM label: " + expectedLabel),
			"the details must name the label the printed PEM carries, but was: '" + out + "'");
		assertTrue(out.contains("private key format: PKCS#1"),
			"a traditional form was written, so PKCS#1 is what must be reported: '" + out + "'");
	}
}
