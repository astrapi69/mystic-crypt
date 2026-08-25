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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Unit tests for the {@code verify-signature} subcommand. The exit code is the contract: 0 for a
 * valid signature, 1 for an invalid one.
 */
class VerifySignatureCommandTest extends AbstractCliTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	/**
	 * Prepares a signed file: generates a key pair, writes both PEM files, writes the data file and
	 * signs it through the {@code sign} subcommand. Returns the involved files as (private PEM,
	 * public PEM, data, signature).
	 */
	private File[] signedSetup(File tempDir, String algorithm) throws Exception
	{
		KeyPair keyPair = SignCommandTest.newKeyPair(algorithm);
		File[] pemFiles = SignCommandTest.writePemFiles(tempDir, keyPair);
		File dataFile = new File(tempDir, "data.txt");
		Files.writeString(dataFile.toPath(), "verify me, " + algorithm);
		File signatureFile = new File(tempDir, "data.sig");
		assertEquals(0,
			run("sign", "--algorithm", algorithm, "--key", pemFiles[0].getAbsolutePath(), "--in",
				dataFile.getAbsolutePath(), "--signature", signatureFile.getAbsolutePath()));
		return new File[] { pemFiles[0], pemFiles[1], dataFile, signatureFile };
	}

	@ParameterizedTest
	@ValueSource(strings = { "Ed25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128F",
			"SLH-DSA-SHAKE-128F" })
	void aValidSignatureVerifiesWithExitCodeZero(String algorithm, @TempDir File tempDir)
		throws Exception
	{
		File[] files = signedSetup(tempDir, algorithm);
		assertEquals(0,
			run("verify-signature", "--algorithm", algorithm, "--key", files[1].getAbsolutePath(),
				"--in", files[2].getAbsolutePath(), "--signature", files[3].getAbsolutePath()));
		assertTrue(out.contains("signature is valid"),
			"stdout must report a valid signature, but was: '" + out + "'");
	}

	@ParameterizedTest
	@ValueSource(strings = { "Ed25519", "ML-DSA-65" })
	void tamperedDataFailsWithExitCodeOne(String algorithm, @TempDir File tempDir) throws Exception
	{
		File[] files = signedSetup(tempDir, algorithm);
		Files.writeString(files[2].toPath(), "tampered after signing");
		assertEquals(1,
			run("verify-signature", "--algorithm", algorithm, "--key", files[1].getAbsolutePath(),
				"--in", files[2].getAbsolutePath(), "--signature", files[3].getAbsolutePath()),
			"an invalid signature must yield exactly exit code 1");
		assertTrue(out.contains("signature is invalid"),
			"stdout must report an invalid signature, but was: '" + out + "'");
	}

	@ParameterizedTest
	@ValueSource(strings = { "Ed25519", "ML-DSA-65" })
	void aTamperedSignatureFailsWithExitCodeOne(String algorithm, @TempDir File tempDir)
		throws Exception
	{
		File[] files = signedSetup(tempDir, algorithm);
		byte[] signature = Files.readAllBytes(files[3].toPath());
		signature[signature.length - 1] ^= 0x01;
		Files.write(files[3].toPath(), signature);
		assertEquals(1,
			run("verify-signature", "--algorithm", algorithm, "--key", files[1].getAbsolutePath(),
				"--in", files[2].getAbsolutePath(), "--signature", files[3].getAbsolutePath()));
		assertTrue(out.contains("signature is invalid"));
	}

	@Test
	void theWrongPublicKeyFailsWithExitCodeOne(@TempDir File tempDir) throws Exception
	{
		File[] files = signedSetup(tempDir, "Ed25519");
		// a second, unrelated key pair - its public key must not verify the signature
		File otherDir = new File(tempDir, "other");
		assertTrue(otherDir.mkdir());
		File otherPublicPem = SignCommandTest.writePemFiles(otherDir,
			SignCommandTest.newKeyPair("Ed25519"))[1];

		assertEquals(1,
			run("verify-signature", "--algorithm", "Ed25519", "--key",
				otherPublicPem.getAbsolutePath(), "--in", files[2].getAbsolutePath(), "--signature",
				files[3].getAbsolutePath()));
		assertTrue(out.contains("signature is invalid"));
	}

	@Test
	void theDataCanComeFromStandardInput(@TempDir File tempDir) throws Exception
	{
		File[] files = signedSetup(tempDir, "Ed25519");
		String data = Files.readString(files[2].toPath());
		assertEquals(0, runWithStdin(data, "verify-signature", "--algorithm", "Ed25519", "--key",
			files[1].getAbsolutePath(), "--in", "-", "--signature", files[3].getAbsolutePath()));
		assertTrue(out.contains("signature is valid"));
	}

	@Test
	void aKeyFileThatIsNoPemKeyFails(@TempDir File tempDir) throws Exception
	{
		File[] files = signedSetup(tempDir, "Ed25519");
		File garbageKey = new File(tempDir, "garbage.pem");
		Files.writeString(garbageKey.toPath(), "this is not a key");
		assertEquals(2,
			run("verify-signature", "--algorithm", "Ed25519", "--key", garbageKey.getAbsolutePath(),
				"--in", files[2].getAbsolutePath(), "--signature", files[3].getAbsolutePath()),
			"an error before verification must exit with 2, never with the 'invalid' code 1");
		assertTrue(err.contains("could not read a Ed25519 public key"),
			"the error must name the unreadable key file, but was: '" + err + "'");
	}

	@Test
	void aNonSignatureAlgorithmIsRejected(@TempDir File tempDir) throws Exception
	{
		File[] files = signedSetup(tempDir, "Ed25519");
		assertEquals(2,
			run("verify-signature", "--algorithm", "ML-KEM-768", "--key",
				files[1].getAbsolutePath(), "--in", files[2].getAbsolutePath(), "--signature",
				files[3].getAbsolutePath()),
			"an error before verification must exit with 2, never with the 'invalid' code 1");
		assertTrue(err.contains("is not a supported signature algorithm"),
			"the error must reject the algorithm, but was: '" + err + "'");
	}

	@Test
	void aMissingSignatureFileFails(@TempDir File tempDir) throws Exception
	{
		File[] files = signedSetup(tempDir, "Ed25519");
		assertEquals(2,
			run("verify-signature", "--algorithm", "Ed25519", "--key", files[1].getAbsolutePath(),
				"--in", files[2].getAbsolutePath(), "--signature",
				new File(tempDir, "no-such.sig").getAbsolutePath()),
			"an error before verification must exit with 2, never with the 'invalid' code 1");
	}
}
