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
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.crypt.data.key.writer.PrivateKeyWriter;
import io.github.astrapi69.crypt.data.key.writer.PublicKeyWriter;
import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Unit tests for {@code sign} and {@code verify-signature} with the classical families, which the
 * commands gained alongside the post-quantum ones, and with key files in DER as well as PEM.
 */
class ClassicalSignatureCommandTest extends AbstractCliTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	/** Generates a key pair through Bouncy Castle, as the UI and the commands do. */
	private static KeyPair newKeyPair(String keyAlgorithm) throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance(keyAlgorithm,
			BouncyCastleProvider.PROVIDER_NAME);
		if ("EC".equals(keyAlgorithm))
		{
			// a NAMED curve, which is the shape SunEC rejects when it is asked to sign with it
			generator.initialize(new ECGenParameterSpec("secp256r1"));
		}
		else
		{
			generator.initialize("DSA".equals(keyAlgorithm) ? 2048 : 2048);
		}
		return generator.generateKeyPair();
	}

	private static File[] writePem(File tempDir, KeyPair keyPair) throws Exception
	{
		File privatePem = new File(tempDir, "private.pem");
		File publicPem = new File(tempDir, "public.pem");
		PrivateKeyWriter.writeInPemFormat(keyPair.getPrivate(), privatePem);
		PublicKeyWriter.writeInPemFormat(keyPair.getPublic(), publicPem);
		return new File[] { privatePem, publicPem };
	}

	private static File[] writeDer(File tempDir, KeyPair keyPair) throws Exception
	{
		File privateDer = new File(tempDir, "private.der");
		File publicDer = new File(tempDir, "public.der");
		Files.write(privateDer.toPath(), keyPair.getPrivate().getEncoded());
		Files.write(publicDer.toPath(), keyPair.getPublic().getEncoded());
		return new File[] { privateDer, publicDer };
	}

	private static File dataFile(File tempDir) throws Exception
	{
		File data = new File(tempDir, "data.txt");
		Files.writeString(data.toPath(), "the bytes that get signed", StandardCharsets.UTF_8);
		return data;
	}

	@ParameterizedTest
	@CsvSource({ "RSA, RSA", "EC, EC", "ECDSA, EC", "DSA, DSA", "SHA512withRSA, RSA" })
	void signAndVerifyRoundTripWithPemKeys(String algorithm, String keyAlgorithm,
		@TempDir File tempDir) throws Exception
	{
		KeyPair keyPair = newKeyPair(keyAlgorithm);
		File[] keys = writePem(tempDir, keyPair);
		File data = dataFile(tempDir);
		File signature = new File(tempDir, "data.sig");

		assertEquals(0, run("sign", "-a", algorithm, "--key", keys[0].getPath(), "--in",
			data.getPath(), "--signature", signature.getPath()), "stderr was: '" + err + "'");

		assertEquals(0, run("verify-signature", "-a", algorithm, "--key", keys[1].getPath(), "--in",
			data.getPath(), "--signature", signature.getPath()), "stderr was: '" + err + "'");
		assertTrue(out.contains("signature is valid"), "stdout was: '" + out + "'");
	}

	@ParameterizedTest
	@ValueSource(strings = { "RSA", "EC", "DSA" })
	void signAndVerifyRoundTripWithDerKeys(String keyAlgorithm, @TempDir File tempDir)
		throws Exception
	{
		KeyPair keyPair = newKeyPair(keyAlgorithm);
		File[] keys = writeDer(tempDir, keyPair);
		File data = dataFile(tempDir);
		File signature = new File(tempDir, "data.sig");

		assertEquals(0, run("sign", "-a", keyAlgorithm, "--key", keys[0].getPath(), "--in",
			data.getPath(), "--signature", signature.getPath()), "stderr was: '" + err + "'");

		assertEquals(0, run("verify-signature", "-a", keyAlgorithm, "--key", keys[1].getPath(),
			"--in", data.getPath(), "--signature", signature.getPath()),
			"stderr was: '" + err + "'");
		assertTrue(out.contains("signature is valid"));
	}

	/**
	 * The trap this pins: an EC key on a named curve, generated by Bouncy Castle, is rejected by
	 * the JDK's SunEC provider when it signs, and verification with it returns false rather than
	 * throwing - a valid signature would read as an invalid one with nothing saying why. Signing,
	 * verifying and decoding all go through Bouncy Castle so this round trip holds.
	 */
	@Test
	void anEcKeyOnANamedCurveSignsAndVerifiesRatherThanReadingAsInvalid(@TempDir File tempDir)
		throws Exception
	{
		KeyPair keyPair = newKeyPair("EC");
		File[] keys = writePem(tempDir, keyPair);
		File data = dataFile(tempDir);
		File signature = new File(tempDir, "data.sig");

		assertEquals(0, run("sign", "-a", "EC", "--key", keys[0].getPath(), "--in", data.getPath(),
			"--signature", signature.getPath()), "stderr was: '" + err + "'");
		int exitCode = run("verify-signature", "-a", "EC", "--key", keys[1].getPath(), "--in",
			data.getPath(), "--signature", signature.getPath());

		assertEquals(0, exitCode,
			"a named-curve EC signature must read as valid, not as invalid; stdout was: '" + out
				+ "', stderr was: '" + err + "'");
		assertTrue(out.contains("signature is valid"));
	}

	/** ECDSA and EC name the same family, so a key written under one verifies under the other. */
	@Test
	void ecdsaAndEcNameTheSameFamily(@TempDir File tempDir) throws Exception
	{
		KeyPair keyPair = newKeyPair("EC");
		File[] keys = writePem(tempDir, keyPair);
		File data = dataFile(tempDir);
		File signature = new File(tempDir, "data.sig");

		assertEquals(0, run("sign", "-a", "ECDSA", "--key", keys[0].getPath(), "--in",
			data.getPath(), "--signature", signature.getPath()), "stderr was: '" + err + "'");

		assertEquals(0, run("verify-signature", "-a", "EC", "--key", keys[1].getPath(), "--in",
			data.getPath(), "--signature", signature.getPath()), "stderr was: '" + err + "'");
	}

	@Test
	void aSignatureOfAnotherKeyIsInvalidRatherThanAnError(@TempDir File tempDir) throws Exception
	{
		KeyPair signing = newKeyPair("RSA");
		KeyPair other = newKeyPair("RSA");
		File data = dataFile(tempDir);
		File signature = new File(tempDir, "data.sig");
		File privatePem = new File(tempDir, "signing-private.pem");
		File otherPublicPem = new File(tempDir, "other-public.pem");
		PrivateKeyWriter.writeInPemFormat(signing.getPrivate(), privatePem);
		PublicKeyWriter.writeInPemFormat(other.getPublic(), otherPublicPem);

		assertEquals(0, run("sign", "-a", "RSA", "--key", privatePem.getPath(), "--in",
			data.getPath(), "--signature", signature.getPath()));

		assertEquals(1,
			run("verify-signature", "-a", "RSA", "--key", otherPublicPem.getPath(), "--in",
				data.getPath(), "--signature", signature.getPath()),
			"a signature of another key is the negative answer, stderr was: '" + err + "'");
		assertTrue(out.contains("signature is invalid"));
	}

	@Test
	void alteredDataMakesTheSignatureInvalid(@TempDir File tempDir) throws Exception
	{
		KeyPair keyPair = newKeyPair("EC");
		File[] keys = writePem(tempDir, keyPair);
		File data = dataFile(tempDir);
		File signature = new File(tempDir, "data.sig");
		assertEquals(0, run("sign", "-a", "EC", "--key", keys[0].getPath(), "--in", data.getPath(),
			"--signature", signature.getPath()));

		Files.writeString(data.toPath(), "the bytes that got changed", StandardCharsets.UTF_8);

		assertEquals(1, run("verify-signature", "-a", "EC", "--key", keys[1].getPath(), "--in",
			data.getPath(), "--signature", signature.getPath()));
	}

	@Test
	void twoRsaSignaturesOfTheSameDataAreTheSameBecauseRsaIsDeterministic(@TempDir File tempDir)
		throws Exception
	{
		KeyPair keyPair = newKeyPair("RSA");
		File[] keys = writePem(tempDir, keyPair);
		File data = dataFile(tempDir);
		File first = new File(tempDir, "first.sig");
		File second = new File(tempDir, "second.sig");

		assertEquals(0, run("sign", "-a", "RSA", "--key", keys[0].getPath(), "--in", data.getPath(),
			"--signature", first.getPath()));
		assertEquals(0, run("sign", "-a", "RSA", "--key", keys[0].getPath(), "--in", data.getPath(),
			"--signature", second.getPath()));

		assertEquals(java.util.HexFormat.of().formatHex(Files.readAllBytes(first.toPath())),
			java.util.HexFormat.of().formatHex(Files.readAllBytes(second.toPath())),
			"PKCS#1 v1.5 RSA signing is deterministic, unlike ECDSA and DSA");
	}

	@Test
	void aKeyFileThatHoldsNoKeyIsNamedAsSuch(@TempDir File tempDir) throws Exception
	{
		File notAKey = new File(tempDir, "not-a-key.pem");
		Files.writeString(notAKey.toPath(), "just some text", StandardCharsets.UTF_8);
		File data = dataFile(tempDir);

		assertNotEquals(0, run("sign", "-a", "RSA", "--key", notAKey.getPath(), "--in",
			data.getPath(), "--signature", new File(tempDir, "x.sig").getPath()));
		assertTrue(err.contains("private key"), "stderr was: '" + err + "'");
	}

	@Test
	void aPublicKeyWhereThePrivateOneBelongsIsRefused(@TempDir File tempDir) throws Exception
	{
		KeyPair keyPair = newKeyPair("RSA");
		File[] keys = writePem(tempDir, keyPair);
		File data = dataFile(tempDir);

		assertNotEquals(0, run("sign", "-a", "RSA", "--key", keys[1].getPath(), "--in",
			data.getPath(), "--signature", new File(tempDir, "x.sig").getPath()));
		assertTrue(err.contains("not a private key") || err.contains("private key"),
			"stderr was: '" + err + "'");
	}
}
