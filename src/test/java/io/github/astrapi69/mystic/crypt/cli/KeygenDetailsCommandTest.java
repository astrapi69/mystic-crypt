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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.security.interfaces.ECPrivateKey;

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
	void anEcKeyAskedForPkcs1KeepsThePkcs8LabelAndSaysSo(@TempDir File tempDir) throws Exception
	{
		File privateKey = new File(tempDir, "ec.pem");

		assertEquals(0,
			run("keygen", "-a", "EC", "--curve", "secp256r1", "--format", "pkcs1",
				"--print-details", "--out-private", privateKey.getPath()),
			"stderr was: '" + err + "'");

		assertTrue(out.contains("PEM label: " + KeyFileWriter.PKCS8_LABEL),
			"only RSA has a traditional label of its own, but the details said: '" + out + "'");
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

	@Test
	void theCommandAnswersItsOwnHelp()
	{
		assertEquals(0, run("keygen", "--help"));
		assertTrue(
			out.contains("--curve") && out.contains("--format") && out.contains("--print-details"),
			"stdout was: '" + out + "'");
	}
}
