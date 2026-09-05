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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
 * Unit tests for the {@code convert} subcommand: what it says a file is, and what it turns it into.
 */
class ConvertCommandTest extends AbstractCliTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	private static KeyPair keyPair(String algorithm) throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm,
			BouncyCastleProvider.PROVIDER_NAME);
		generator.initialize(2048);
		return generator.generateKeyPair();
	}

	private static File writeDerPrivate(File tempDir, KeyPair keyPair) throws Exception
	{
		File der = new File(tempDir, "private.der");
		Files.write(der.toPath(), keyPair.getPrivate().getEncoded());
		return der;
	}

	@Test
	void describesADerPrivateKeyWithoutChangingIt(@TempDir File tempDir) throws Exception
	{
		File der = writeDerPrivate(tempDir, keyPair("RSA"));
		byte[] before = Files.readAllBytes(der.toPath());

		assertEquals(0, run("convert", "--in", der.getPath(), "--describe"),
			"stderr was: '" + err + "'");

		assertTrue(out.contains("private key in PKCS#8"), "stdout was: '" + out + "'");
		assertTrue(out.contains("DER"), "stdout was: '" + out + "'");
		assertArrayEquals(before, Files.readAllBytes(der.toPath()),
			"--describe must change nothing");
	}

	@Test
	void namesWhatItFoundBeforeConverting(@TempDir File tempDir) throws Exception
	{
		File der = writeDerPrivate(tempDir, keyPair("RSA"));
		File pem = new File(tempDir, "private.pem");

		assertEquals(0,
			run("convert", "--in", der.getPath(), "--to", "pkcs8", "--out", pem.getPath()),
			"stderr was: '" + err + "'");

		assertTrue(err.contains("is a private key in PKCS#8"),
			"the run must say what it found first, but was: '" + err + "'");
		assertTrue(err.contains("wrote PEM"), "stderr was: '" + err + "'");
	}

	/**
	 * The defect this pins: asking for PKCS#8 must produce PKCS#8. crypt-data's PrivateKeyWriter
	 * strips the wrapper and writes PKCS#1 under an RSA PRIVATE KEY header instead, which is why
	 * the writing here does not go through it.
	 */
	@Test
	void askingForPkcs8ProducesPkcs8AndAskingForPkcs1ProducesPkcs1(@TempDir File tempDir)
		throws Exception
	{
		KeyPair keyPair = keyPair("RSA");
		File der = writeDerPrivate(tempDir, keyPair);
		File asPkcs8 = new File(tempDir, "pkcs8.pem");
		File asPkcs1 = new File(tempDir, "pkcs1.pem");

		assertEquals(0,
			run("convert", "--in", der.getPath(), "--to", "pkcs8", "--out", asPkcs8.getPath()));
		assertEquals(0,
			run("convert", "--in", der.getPath(), "--to", "pkcs1", "--out", asPkcs1.getPath()));

		String pkcs8 = Files.readString(asPkcs8.toPath(), StandardCharsets.UTF_8);
		String pkcs1 = Files.readString(asPkcs1.toPath(), StandardCharsets.UTF_8);

		assertTrue(pkcs8.contains("-----BEGIN " + KeyFileWriter.PKCS8_LABEL + "-----"),
			"PKCS#8 must be written under the PRIVATE KEY header, but was: '" + pkcs8 + "'");
		assertTrue(pkcs1.contains("-----BEGIN " + KeyFileWriter.PKCS1_RSA_LABEL + "-----"),
			"PKCS#1 must be written under the RSA PRIVATE KEY header, but was: '" + pkcs1 + "'");

		// and both are still the same key
		assertArrayEquals(keyPair.getPrivate().getEncoded(),
			KeyFileReader.readPrivateKey(asPkcs8, "RSA").getEncoded());
		assertArrayEquals(keyPair.getPrivate().getEncoded(),
			KeyFileReader.readPrivateKey(asPkcs1, "RSA").getEncoded());
	}

	@Test
	void aPrivateKeyRoundTripsThroughPemAndBackToDer(@TempDir File tempDir) throws Exception
	{
		KeyPair keyPair = keyPair("RSA");
		File der = writeDerPrivate(tempDir, keyPair);
		File pem = new File(tempDir, "round.pem");
		File backToDer = new File(tempDir, "round.der");

		assertEquals(0,
			run("convert", "--in", der.getPath(), "--to", "pem", "--out", pem.getPath()));
		assertEquals(0,
			run("convert", "--in", pem.getPath(), "--to", "der", "--out", backToDer.getPath()));

		assertArrayEquals(Files.readAllBytes(der.toPath()), Files.readAllBytes(backToDer.toPath()),
			"a round trip through PEM must give back the same DER bytes");
	}

	@Test
	void aPublicKeyConvertsBothWays(@TempDir File tempDir) throws Exception
	{
		KeyPair keyPair = keyPair("RSA");
		File der = new File(tempDir, "public.der");
		Files.write(der.toPath(), keyPair.getPublic().getEncoded());
		File pem = new File(tempDir, "public.pem");
		File backToDer = new File(tempDir, "public-back.der");

		assertEquals(0, run("convert", "--in", der.getPath(), "--describe"));
		assertTrue(out.contains("a public key"), "stdout was: '" + out + "'");

		assertEquals(0,
			run("convert", "--in", der.getPath(), "--to", "pem", "--out", pem.getPath()));
		assertEquals(0,
			run("convert", "--in", pem.getPath(), "--to", "der", "--out", backToDer.getPath()));
		assertArrayEquals(keyPair.getPublic().getEncoded(), Files.readAllBytes(backToDer.toPath()));
	}

	@Test
	void aCertificateConvertsBothWays(@TempDir File tempDir) throws Exception
	{
		File certificatePem = new File(tempDir, "cert.pem");
		assertEquals(0, run("cert", "--subject", "CN=convert-test", "--days", "1", "--out",
			certificatePem.getPath()), "stderr was: '" + err + "'");
		File certificateDer = new File(tempDir, "cert.der");
		File backToPem = new File(tempDir, "cert-back.pem");

		assertEquals(0, run("convert", "--in", certificatePem.getPath(), "--describe"));
		assertTrue(out.contains("X.509 certificate"), "stdout was: '" + out + "'");

		assertEquals(0, run("convert", "--in", certificatePem.getPath(), "--to", "der", "--out",
			certificateDer.getPath()), "stderr was: '" + err + "'");
		assertEquals(0, run("convert", "--in", certificateDer.getPath(), "--to", "pem", "--out",
			backToPem.getPath()), "stderr was: '" + err + "'");

		assertTrue(Files.readString(backToPem.toPath()).contains("-----BEGIN CERTIFICATE-----"));
	}

	@ParameterizedTest
	@ValueSource(strings = { "pkcs1", "pkcs8" })
	void askingForAPrivateKeyWrappingOfAPublicKeySaysWhyThatMakesNoSense(String target,
		@TempDir File tempDir) throws Exception
	{
		File der = new File(tempDir, "public.der");
		Files.write(der.toPath(), keyPair("RSA").getPublic().getEncoded());

		assertEquals(2, run("convert", "--in", der.getPath(), "--to", target, "--out",
			new File(tempDir, "x").getPath()));
		assertTrue(err.contains("PRIVATE key") || err.contains("private key"),
			"the message must explain the mismatch, but was: '" + err + "'");
	}

	@Test
	void derCannotBePrintedAndSaysSo(@TempDir File tempDir) throws Exception
	{
		File der = writeDerPrivate(tempDir, keyPair("RSA"));

		assertEquals(2, run("convert", "--in", der.getPath(), "--to", "der"));
		assertTrue(err.contains("--out"),
			"the message must say how to get it, but was: '" + err + "'");
	}

	@Test
	void withoutATargetItSaysWhatItIsAndThatNothingWasConverted(@TempDir File tempDir)
		throws Exception
	{
		File der = writeDerPrivate(tempDir, keyPair("RSA"));

		assertEquals(0, run("convert", "--in", der.getPath()));

		assertTrue(err.contains("nothing was converted"), "stderr was: '" + err + "'");
		assertTrue(err.contains("--to"), "stderr was: '" + err + "'");
	}

	@Test
	void aFileThatIsNeitherKeyNorCertificateIsNamedAsSuch(@TempDir File tempDir) throws Exception
	{
		File rubbish = new File(tempDir, "rubbish.bin");
		Files.write(rubbish.toPath(), new byte[] { 9, 9, 9, 9 });

		assertEquals(2, run("convert", "--in", rubbish.getPath(), "--describe"));
		assertTrue(err.contains("not a DER"), "stderr was: '" + err + "'");
	}

	@Test
	void printedPemGoesToStandardOutputWhenNoFileIsGiven(@TempDir File tempDir) throws Exception
	{
		File der = writeDerPrivate(tempDir, keyPair("RSA"));

		assertEquals(0, run("convert", "--in", der.getPath(), "--to", "pkcs8"));

		assertTrue(out.contains("-----BEGIN PRIVATE KEY-----"), "stdout was: '" + out + "'");
	}

	@Test
	void der2pemStillWorksAndSaysItIsDeprecated()
	{
		assertEquals(0, run("der2pem", "--help"));
		assertTrue(out.contains("Deprecated"),
			"the old command must point at the new one, but was: '" + out + "'");
	}

	/**
	 * A traditional PKCS#1 PEM is the other private key shape a file arrives in, and every target
	 * has to work from it too. Converting only the encoding must keep the wrapping it had, so that
	 * asking for PEM does not silently restructure the key as well.
	 */
	@Test
	void aPkcs1PemConvertsToEveryTargetAndKeepsItsWrappingUnderPem(@TempDir File tempDir)
		throws Exception
	{
		KeyPair keyPair = keyPair("RSA");
		File pkcs1 = new File(tempDir, "pkcs1.pem");
		Files.writeString(pkcs1.toPath(), KeyFileWriter.toPem(keyPair.getPrivate(), true),
			StandardCharsets.UTF_8);

		assertEquals(0, run("convert", "--in", pkcs1.getPath(), "--describe"));
		assertTrue(out.contains("PKCS#1"), "stdout was: '" + out + "'");

		File stillPkcs1 = new File(tempDir, "still-pkcs1.pem");
		assertEquals(0,
			run("convert", "--in", pkcs1.getPath(), "--to", "pem", "--out", stillPkcs1.getPath()),
			"stderr was: '" + err + "'");
		assertTrue(
			Files.readString(stillPkcs1.toPath())
				.contains("-----BEGIN " + KeyFileWriter.PKCS1_RSA_LABEL + "-----"),
			"--to pem must not change the wrapping");

		File asPkcs8 = new File(tempDir, "as-pkcs8.pem");
		assertEquals(0,
			run("convert", "--in", pkcs1.getPath(), "--to", "pkcs8", "--out", asPkcs8.getPath()));
		assertTrue(Files.readString(asPkcs8.toPath())
			.contains("-----BEGIN " + KeyFileWriter.PKCS8_LABEL + "-----"));

		File asDer = new File(tempDir, "as.der");
		assertEquals(0,
			run("convert", "--in", pkcs1.getPath(), "--to", "der", "--out", asDer.getPath()));
		assertArrayEquals(keyPair.getPrivate().getEncoded(), Files.readAllBytes(asDer.toPath()));
	}

	/**
	 * An EC key asked for the traditional form gets the label that belongs to it.
	 * <p>
	 * This asserted the opposite while the conversions lived in KeyFileWriter, on the premise that
	 * only RSA has a traditional label of its own. That premise was wrong: an ec key has RFC 5915
	 * and the EC PRIVATE KEY label, which is what openssl writes and reads. crypt-data picks the
	 * label from the key rather than from its bytes, so the file says what it holds.
	 */
	@Test
	void anEcKeyAskedForPkcs1GetsTheEcLabel(@TempDir File tempDir) throws Exception
	{
		java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("EC",
			BouncyCastleProvider.PROVIDER_NAME);
		generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
		KeyPair keyPair = generator.generateKeyPair();
		File der = new File(tempDir, "ec.der");
		Files.write(der.toPath(), keyPair.getPrivate().getEncoded());
		File pem = new File(tempDir, "ec-pkcs1.pem");

		assertEquals(0,
			run("convert", "--in", der.getPath(), "--to", "pkcs1", "--out", pem.getPath()),
			"stderr was: '" + err + "'");

		String written = Files.readString(pem.toPath());
		assertTrue(written.startsWith("-----BEGIN EC PRIVATE KEY-----"),
			"an ec key has a traditional label of its own, but the file began '"
				+ written.lines().findFirst().orElse("") + "'");
		assertArrayEquals(
			io.github.astrapi69.crypt.data.key.PrivateKeyExtensions
				.toPKCS1Format(keyPair.getPrivate()),
			java.util.Base64.getDecoder()
				.decode(written.replaceAll("-----[A-Z0-9 ]+-----", "").replaceAll("\\s", "")),
			"and the body must be the traditional encoding that label names");
	}

	@Test
	void aCertificateHasNoPrivateKeyWrappingToAskFor(@TempDir File tempDir) throws Exception
	{
		File certificatePem = new File(tempDir, "cert.pem");
		assertEquals(0, run("cert", "--subject", "CN=convert-test", "--days", "1", "--out",
			certificatePem.getPath()));

		assertEquals(2, run("convert", "--in", certificatePem.getPath(), "--to", "pkcs8", "--out",
			new File(tempDir, "x").getPath()));
		assertTrue(err.contains("certificate has neither"),
			"the message must explain the mismatch, but was: '" + err + "'");
	}

	@Test
	void aCertificateCanBeRewrittenAsPemFromPem(@TempDir File tempDir) throws Exception
	{
		File certificatePem = new File(tempDir, "cert.pem");
		assertEquals(0, run("cert", "--subject", "CN=convert-test", "--days", "1", "--out",
			certificatePem.getPath()));
		File rewritten = new File(tempDir, "cert-again.pem");

		assertEquals(0, run("convert", "--in", certificatePem.getPath(), "--to", "pem", "--out",
			rewritten.getPath()), "stderr was: '" + err + "'");

		assertTrue(Files.readString(rewritten.toPath()).contains("-----BEGIN CERTIFICATE-----"));
	}

	@Test
	void aPemHoldingSomethingThatIsNeitherKeyNorCertificateIsNamed(@TempDir File tempDir)
		throws Exception
	{
		File pem = new File(tempDir, "odd.pem");
		Files.writeString(pem.toPath(), "text -----BEGIN something odd" + System.lineSeparator(),
			StandardCharsets.UTF_8);

		assertEquals(2, run("convert", "--in", pem.getPath(), "--describe"));
		assertTrue(err.contains("no PEM object"), "stderr was: '" + err + "'");
	}

	@Test
	void aPemHoldingAWellFormedObjectThatIsNoKeyIsNamedByItsType(@TempDir File tempDir)
		throws Exception
	{
		// EC PARAMETERS parses cleanly into a curve identifier: a well formed PEM object that is
		// neither a key nor a certificate, which is the case the message exists for
		byte[] secp256r1 = { 0x06, 0x08, 0x2A, (byte)0x86, 0x48, (byte)0xCE, 0x3D, 0x03, 0x01,
				0x07 };
		File pem = new File(tempDir, "params.pem");
		Files.writeString(pem.toPath(), KeyFileWriter.toPem("EC PARAMETERS", secp256r1),
			StandardCharsets.UTF_8);

		assertEquals(2, run("convert", "--in", pem.getPath(), "--describe"));
		assertTrue(err.contains("not a key or a certificate"),
			"the message must say what it holds, but was: '" + err + "'");
	}

	@Test
	void aPemWhoseBodyDoesNotMatchItsArmourIsNamedAsUnreadable(@TempDir File tempDir)
		throws Exception
	{
		File pem = new File(tempDir, "broken.pem");
		Files.writeString(pem.toPath(),
			"-----BEGIN CERTIFICATE-----" + System.lineSeparator() + "!!!not base64!!!"
				+ System.lineSeparator() + "-----END CERTIFICATE-----" + System.lineSeparator(),
			StandardCharsets.UTF_8);

		assertEquals(2, run("convert", "--in", pem.getPath(), "--describe"));
		assertTrue(err.contains("could not read a PEM object"),
			"the message must say the body could not be read, but was: '" + err + "'");
	}

	/**
	 * The confirmation names the wrapping that was actually written, which is how a reader sees
	 * that --to pem kept the input's own wrapping instead of silently changing it.
	 */
	@Test
	void theConfirmationNamesTheWrappingThatWasWritten(@TempDir File tempDir) throws Exception
	{
		KeyPair keyPair = keyPair("RSA");
		File pkcs8Der = writeDerPrivate(tempDir, keyPair);
		File pkcs1Pem = new File(tempDir, "in-pkcs1.pem");
		Files.writeString(pkcs1Pem.toPath(), KeyFileWriter.toPem(keyPair.getPrivate(), true),
			StandardCharsets.UTF_8);

		assertEquals(0, run("convert", "--in", pkcs8Der.getPath(), "--to", "pem", "--out",
			new File(tempDir, "a.pem").getPath()));
		assertTrue(err.contains("wrote PEM, PKCS#8"), "stderr was: '" + err + "'");

		assertEquals(0, run("convert", "--in", pkcs1Pem.getPath(), "--to", "pem", "--out",
			new File(tempDir, "b.pem").getPath()));
		assertTrue(err.contains("wrote PEM, PKCS#1"), "stderr was: '" + err + "'");
	}

	/**
	 * A certificate reaches the conversion from either encoding, and the bytes have to be the same
	 * either way - otherwise one of the two paths is reading something else.
	 */
	@Test
	void aCertificateGivesTheSameDerWhicheverEncodingItArrivedIn(@TempDir File tempDir)
		throws Exception
	{
		File asPem = new File(tempDir, "cert.pem");
		assertEquals(0,
			run("cert", "--subject", "CN=either", "--days", "1", "--out", asPem.getPath()));
		File fromPem = new File(tempDir, "from-pem.der");
		assertEquals(0,
			run("convert", "--in", asPem.getPath(), "--to", "der", "--out", fromPem.getPath()));

		File fromDer = new File(tempDir, "from-der.der");
		assertEquals(0,
			run("convert", "--in", fromPem.getPath(), "--to", "der", "--out", fromDer.getPath()),
			"stderr was: '" + err + "'");

		assertArrayEquals(Files.readAllBytes(fromPem.toPath()),
			Files.readAllBytes(fromDer.toPath()),
			"the DER of a certificate must not depend on how it was handed in");

		// and it has to be DER rather than the armoured text handed straight through: a DER
		// certificate begins with an ASN.1 SEQUENCE and carries no BEGIN line
		byte[] der = Files.readAllBytes(fromPem.toPath());
		assertEquals(0x30, der[0] & 0xff, "DER starts with a SEQUENCE tag");
		assertFalse(new String(der, StandardCharsets.UTF_8).contains("BEGIN CERTIFICATE"),
			"the PEM armour must be gone, not passed through");
	}

	/**
	 * The description names the algorithm the file carries, which is the part that tells a reader
	 * whether they are looking at the key they think they are.
	 */
	@Test
	void theDescriptionNamesTheAlgorithmOfTheKey(@TempDir File tempDir) throws Exception
	{
		File rsa = writeDerPrivate(tempDir, keyPair("RSA"));

		assertEquals(0, run("convert", "--in", rsa.getPath(), "--describe"));

		assertTrue(out.contains("algorithm 1.2.840.113549.1.1.1"),
			"the RSA object identifier must be named, but the output was: '" + out + "'");
	}

	@Test
	void theCommandAnswersItsOwnHelp()
	{
		assertEquals(0, run("convert", "--help"));
		assertTrue(out.contains("--describe") && out.contains("--to"), "stdout was: '" + out + "'");
	}

	/**
	 * A key whose algorithm has no traditional form cannot be written as PKCS#1. The command used
	 * to write PKCS#8 and announce PKCS#1 anyway, with exit code 0. It must refuse instead, before
	 * anything is written, and name the algorithm. See issue #127.
	 *
	 * @param algorithm
	 *            the KeyPairGeneratorAlgorithm name of a key with no traditional form
	 * @param tempDir
	 *            the directory the key is written to
	 */
	@ParameterizedTest(name = "convert --to pkcs1 refuses {0}")
	@ValueSource(strings = { "ML_DSA_65", "ML_KEM_768", "X25519" })
	void refusesToConvertToPkcs1WhatHasNoTraditionalForm(String algorithm, @TempDir File tempDir)
	{
		File privateKey = new File(tempDir, "key.pem");
		File converted = new File(tempDir, "converted.pem");
		assertEquals(0, run("keygen", "-a", algorithm, "--out-private", privateKey.getPath()),
			"stderr was: '" + err + "'");

		assertEquals(2,
			run("convert", "--in", privateKey.getPath(), "--to", "pkcs1", "--out",
				converted.getPath()),
			"a format that cannot be produced must be an error, not a silent substitution");
		assertFalse(converted.exists(),
			"nothing may be written when the requested format cannot be produced");
		assertTrue(err.contains("PKCS#1") && err.contains("PKCS#8"),
			"the message must name what was asked for and what the key actually has, but was: '"
				+ err + "'");
	}

	/**
	 * The counterpart: an algorithm that does have a traditional form still converts, and the note
	 * names the encoding the file really carries.
	 *
	 * @param algorithm
	 *            an algorithm whose private key has a traditional form
	 * @param expectedLabel
	 *            the PEM label that form carries
	 * @param tempDir
	 *            the directory the key is written to
	 * @throws Exception
	 *             if the key cannot be written or read back
	 */
	@ParameterizedTest(name = "convert --to pkcs1 keeps working for {0}")
	@CsvSource({ "RSA, RSA PRIVATE KEY", "DSA, DSA PRIVATE KEY" })
	void stillConvertsWhatDoesHaveATraditionalForm(String algorithm, String expectedLabel,
		@TempDir File tempDir) throws Exception
	{
		File privateKey = new File(tempDir, "key.pem");
		File converted = new File(tempDir, "converted.pem");
		assertEquals(0, run("keygen", "-a", algorithm, "--out-private", privateKey.getPath()),
			"stderr was: '" + err + "'");

		assertEquals(0, run("convert", "--in", privateKey.getPath(), "--to", "pkcs1", "--out",
			converted.getPath()), "stderr was: '" + err + "'");

		assertEquals("-----BEGIN " + expectedLabel + "-----",
			Files.readAllLines(converted.toPath()).get(0));
		assertTrue(err.contains("PKCS#1"), "the note must name PKCS#1, but was: '" + err + "'");
	}
}
