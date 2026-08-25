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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.key.writer.PrivateKeyWriter;
import io.github.astrapi69.crypt.data.key.writer.PublicKeyWriter;
import io.github.astrapi69.mystic.crypt.key.Ed25519Signer;
import io.github.astrapi69.mystic.crypt.key.Ed25519Verifier;
import io.github.astrapi69.mystic.crypt.key.MlDsaSigner;
import io.github.astrapi69.mystic.crypt.key.MlDsaVerifier;
import io.github.astrapi69.mystic.crypt.key.SlhDsaSigner;
import io.github.astrapi69.mystic.crypt.key.SlhDsaVerifier;
import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Unit tests for the {@code sign} subcommand.
 */
class SignCommandTest extends AbstractCliTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	/**
	 * Generates a key pair of the given signature algorithm family, bypassing the code under test.
	 */
	static KeyPair newKeyPair(String algorithm) throws Exception
	{
		if ("Ed25519".equalsIgnoreCase(algorithm))
		{
			return Ed25519Signer.newKeyPair();
		}
		KeyPairGeneratorAlgorithm parsed = KeyPairGeneratorAlgorithm
			.valueOf(algorithm.toUpperCase().replace('-', '_'));
		return parsed.name().startsWith("ML_DSA")
			? MlDsaSigner.newKeyPair(parsed)
			: SlhDsaSigner.newKeyPair(parsed);
	}

	/** Verifies a signature with the library's verifier classes, bypassing the code under test. */
	static boolean verifyDirectly(String algorithm, KeyPair keyPair, byte[] data, byte[] signature)
		throws Exception
	{
		if ("Ed25519".equalsIgnoreCase(algorithm))
		{
			return new Ed25519Verifier(keyPair.getPublic()).verify(data, signature);
		}
		KeyPairGeneratorAlgorithm parsed = KeyPairGeneratorAlgorithm
			.valueOf(algorithm.toUpperCase().replace('-', '_'));
		return parsed.name().startsWith("ML_DSA")
			? new MlDsaVerifier(keyPair.getPublic(), parsed).verify(data, signature)
			: new SlhDsaVerifier(keyPair.getPublic(), parsed).verify(data, signature);
	}

	/** Writes the key pair as the two PEM files the commands read. */
	static File[] writePemFiles(File tempDir, KeyPair keyPair) throws Exception
	{
		File privatePem = new File(tempDir, "private.pem");
		File publicPem = new File(tempDir, "public.pem");
		PrivateKeyWriter.writeInPemFormat(keyPair.getPrivate(), privatePem);
		PublicKeyWriter.writeInPemFormat(keyPair.getPublic(), publicPem);
		return new File[] { privatePem, publicPem };
	}

	@ParameterizedTest
	@ValueSource(strings = { "Ed25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128F",
			"SLH-DSA-SHAKE-128F" })
	void signsAFileWithEverySignatureFamily(String algorithm, @TempDir File tempDir)
		throws Exception
	{
		KeyPair keyPair = newKeyPair(algorithm);
		File privatePem = writePemFiles(tempDir, keyPair)[0];
		File dataFile = new File(tempDir, "data.txt");
		Files.writeString(dataFile.toPath(), "sign me, " + algorithm);
		File signatureFile = new File(tempDir, "data.sig");

		assertEquals(0, run("sign", "--algorithm", algorithm, "--key", privatePem.getAbsolutePath(),
			"--in", dataFile.getAbsolutePath(), "--signature", signatureFile.getAbsolutePath()));
		assertTrue(out.contains("wrote signature to " + signatureFile.getAbsolutePath()),
			"stdout must confirm the signature file, but was: '" + out + "'");

		byte[] signature = Files.readAllBytes(signatureFile.toPath());
		assertTrue(signature.length > 0, "the signature file must not be empty");
		assertTrue(
			verifyDirectly(algorithm, keyPair, Files.readAllBytes(dataFile.toPath()), signature),
			"the written signature must verify against the data and the public key");
	}

	@Test
	void underscoresAndCaseAreAcceptedInTheAlgorithmName(@TempDir File tempDir) throws Exception
	{
		KeyPair keyPair = newKeyPair("ML-DSA-65");
		File privatePem = writePemFiles(tempDir, keyPair)[0];
		File dataFile = new File(tempDir, "data.txt");
		Files.writeString(dataFile.toPath(), "sign me");
		File signatureFile = new File(tempDir, "data.sig");

		assertEquals(0,
			run("sign", "--algorithm", "ml_dsa_65", "--key", privatePem.getAbsolutePath(), "--in",
				dataFile.getAbsolutePath(), "--signature", signatureFile.getAbsolutePath()));
		assertTrue(verifyDirectly("ML-DSA-65", keyPair, Files.readAllBytes(dataFile.toPath()),
			Files.readAllBytes(signatureFile.toPath())));
	}

	@Test
	void theDataCanComeFromStandardInput(@TempDir File tempDir) throws Exception
	{
		KeyPair keyPair = newKeyPair("Ed25519");
		File privatePem = writePemFiles(tempDir, keyPair)[0];
		File signatureFile = new File(tempDir, "stdin.sig");
		String data = "signed straight from standard input";

		assertEquals(0,
			runWithStdin(data, "sign", "--algorithm", "ed25519", "--key",
				privatePem.getAbsolutePath(), "--in", "-", "--signature",
				signatureFile.getAbsolutePath()));
		assertTrue(
			verifyDirectly("Ed25519", keyPair, data.getBytes(StandardCharsets.UTF_8),
				Files.readAllBytes(signatureFile.toPath())),
			"the signature must cover exactly the bytes read from standard input");
	}

	/** Algorithms that exist but cannot sign - and unknown names - are rejected clearly. */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "EC", "X25519", "ML-KEM-768" })
	void nonSignatureAlgorithmsAreRejected(String algorithm, @TempDir File tempDir) throws Exception
	{
		File dataFile = new File(tempDir, "data.txt");
		Files.writeString(dataFile.toPath(), "data");
		File anyKey = new File(tempDir, "any.pem");
		Files.writeString(anyKey.toPath(), "irrelevant, rejected before reading");

		assertNotEquals(0,
			run("sign", "--algorithm", algorithm, "--key", anyKey.getAbsolutePath(), "--in",
				dataFile.getAbsolutePath(), "--signature",
				new File(tempDir, "out.sig").getAbsolutePath()));
		assertTrue(err.contains("is not a supported signature algorithm"),
			"the error must say '" + algorithm + "' cannot sign, but was: '" + err + "'");
	}

	@Test
	void anUnknownAlgorithmFails(@TempDir File tempDir) throws Exception
	{
		File dataFile = new File(tempDir, "data.txt");
		Files.writeString(dataFile.toPath(), "data");
		assertNotEquals(0,
			run("sign", "--algorithm", "NOPE", "--key", dataFile.getAbsolutePath(), "--in",
				dataFile.getAbsolutePath(), "--signature",
				new File(tempDir, "out.sig").getAbsolutePath()));
		assertTrue(err.contains("unknown key algorithm"),
			"the error must name the unknown algorithm, but was: '" + err + "'");
	}

	@Test
	void aKeyFileThatIsNoPemKeyFails(@TempDir File tempDir) throws Exception
	{
		File garbageKey = new File(tempDir, "garbage.pem");
		Files.writeString(garbageKey.toPath(), "this is not a key");
		File dataFile = new File(tempDir, "data.txt");
		Files.writeString(dataFile.toPath(), "data");

		assertNotEquals(0,
			run("sign", "--algorithm", "Ed25519", "--key", garbageKey.getAbsolutePath(), "--in",
				dataFile.getAbsolutePath(), "--signature",
				new File(tempDir, "out.sig").getAbsolutePath()));
		assertTrue(err.contains("could not read a Ed25519 private key"),
			"the error must name the unreadable key file, but was: '" + err + "'");
	}

	@Test
	void aKeyOfTheWrongAlgorithmFails(@TempDir File tempDir) throws Exception
	{
		// an Ed25519 key cannot be decoded as ML-DSA-65
		File privatePem = writePemFiles(tempDir, newKeyPair("Ed25519"))[0];
		File dataFile = new File(tempDir, "data.txt");
		Files.writeString(dataFile.toPath(), "data");

		assertNotEquals(0,
			run("sign", "--algorithm", "ML-DSA-65", "--key", privatePem.getAbsolutePath(), "--in",
				dataFile.getAbsolutePath(), "--signature",
				new File(tempDir, "out.sig").getAbsolutePath()));
		assertTrue(err.contains("could not read a ML-DSA-65 private key"),
			"the error must name the expected key algorithm, but was: '" + err + "'");
	}

	@Test
	void writingTheSignatureToStandardOutputIsRejected(@TempDir File tempDir) throws Exception
	{
		File privatePem = writePemFiles(tempDir, newKeyPair("Ed25519"))[0];
		File dataFile = new File(tempDir, "data.txt");
		Files.writeString(dataFile.toPath(), "data");
		assertNotEquals(0, run("sign", "--algorithm", "Ed25519", "--key",
			privatePem.getAbsolutePath(), "--in", dataFile.getAbsolutePath(), "--signature", "-"));
		assertTrue(err.contains("standard output is not supported"),
			"the error must reject '-' as signature target, but was: '" + err + "'");
	}

	@Test
	void aMissingInputFileFails(@TempDir File tempDir) throws Exception
	{
		File privatePem = writePemFiles(tempDir, newKeyPair("Ed25519"))[0];
		assertNotEquals(0,
			run("sign", "--algorithm", "Ed25519", "--key", privatePem.getAbsolutePath(), "--in",
				new File(tempDir, "no-such.txt").getAbsolutePath(), "--signature",
				new File(tempDir, "out.sig").getAbsolutePath()));
	}
}
