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
package io.github.astrapi69.mystic.crypt.key;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Unit tests for {@link Signatures}, the public entry point that dispatches by suite identifier to
 * the Ed25519, ML-DSA, SLH-DSA and classical signer families (#149). The tests moved here from the
 * command line package, where the same dispatch used to be package-private.
 */
class SignaturesTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	@ParameterizedTest
	@ValueSource(strings = { "Ed25519", "ed25519", "ED25519", " Ed25519 " })
	void ed25519IsRecognizedInAnyCase(String name)
	{
		assertTrue(Signatures.isEd25519(name));
		assertEquals("Ed25519", Signatures.keyFactoryAlgorithm(name));
	}

	@Test
	void otherAlgorithmNamesAreNotEd25519()
	{
		assertFalse(Signatures.isEd25519("ML-DSA-65"));
	}

	/** The key factory algorithm is the JCA name of the parameter set, dashes included. */
	@ParameterizedTest
	@CsvSource({ "ML-DSA-44, ML-DSA-44", "ml_dsa_65, ML-DSA-65", "ML_DSA_87, ML-DSA-87",
			"SLH-DSA-SHA2-128S, SLH-DSA-SHA2-128S", "slh_dsa_shake_128f, SLH-DSA-SHAKE-128F" })
	void keyFactoryAlgorithmIsTheJcaNameOfTheParameterSet(String input, String expected)
	{
		assertEquals(expected, Signatures.keyFactoryAlgorithm(input));
	}

	/**
	 * Algorithms that exist but cannot sign are rejected with a clear message. RSA, EC and DSA used
	 * to be on this list and no longer are: they sign, through Bouncy Castle. What is left here are
	 * the key-exchange algorithms, which have no signature operation at all.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "X25519", "X448", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" })
	void nonSignatureAlgorithmsAreRejected(String name)
	{
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
			() -> Signatures.keyFactoryAlgorithm(name));
		assertTrue(exception.getMessage().contains("is not a supported signature algorithm"),
			"the message must say why '" + name + "' is rejected, but was: '"
				+ exception.getMessage() + "'");
	}

	/**
	 * A JCA-style name of a family this tool has no signer for is not a classical algorithm, so it
	 * falls through to the post-quantum parser and is rejected there rather than being attempted.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "SHA256withFOO", "nothing at all", "with" })
	void aWithNameOfAnUnknownFamilyIsNotClassical(String algorithm)
	{
		assertFalse(Signatures.isClassical(algorithm));
	}

	@ParameterizedTest
	@ValueSource(strings = { "RSA", "ec", "ECDSA", "DSA", "SHA512withRSA", "SHA256withECDSA" })
	void theClassicalFamiliesAreRecognisedByEitherName(String algorithm)
	{
		assertTrue(Signatures.isClassical(algorithm),
			algorithm + " must be recognised as a classical signature algorithm");
	}

	/**
	 * The key factory algorithm a classical name implies, which is what decides how the key file is
	 * read. ECDSA and EC both mean an EC key.
	 */
	@ParameterizedTest
	@CsvSource({ "RSA, RSA", "ec, EC", "ECDSA, EC", "DSA, DSA", "SHA512withRSA, RSA",
			"SHA256withECDSA, EC" })
	void aClassicalNameImpliesItsKeyFactoryAlgorithm(String algorithm, String expected)
	{
		assertEquals(expected, Signatures.keyFactoryAlgorithm(algorithm));
	}

	/**
	 * A name that begins with "with" has the separator at position zero, which is still a
	 * separator: what follows it is the family.
	 */
	@Test
	void aNameThatBeginsWithTheSeparatorStillNamesItsFamily()
	{
		assertTrue(Signatures.isClassical("withRSA"));
		assertEquals("RSA", Signatures.keyFactoryAlgorithm("withRSA"));
	}

	@Test
	void unknownAlgorithmNamesAreRejected()
	{
		assertThrows(IllegalArgumentException.class, () -> Signatures.keyFactoryAlgorithm("NOPE"));
	}

	/** The sign and verify dispatch must pick the family that belongs to the algorithm name. */
	@ParameterizedTest
	@ValueSource(strings = { "Ed25519", "ML-DSA-65", "SLH-DSA-SHA2-128F", "RSA", "EC",
			"SHA512withRSA", "DSA" })
	void signAndVerifyRoundTripInEveryFamily(String algorithm) throws Exception
	{
		KeyPair keyPair = newKeyPair(algorithm);
		byte[] data = ("round trip " + algorithm).getBytes(StandardCharsets.UTF_8);
		byte[] signature = Signatures.sign(algorithm, keyPair.getPrivate(), data);
		assertTrue(Signatures.verify(algorithm, keyPair.getPublic(), data, signature));
		assertFalse(
			Signatures.verify(algorithm, keyPair.getPublic(), "other data".getBytes(), signature),
			"the signature must not verify against different data");
	}

	/**
	 * Reproduction of #149: a caller that learns the suite at runtime must get a refusal for an
	 * identifier the library does not know - on signing and on verifying alike - never a quiet
	 * {@code false} that reads like an invalid signature. The message names the value.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "NOPE", "", "   ", "X25519", "ML-KEM-768", "SHA256withFOO", "Ed448x" })
	void anUnknownSuiteIsRefusedOnSignAndOnVerify(String suite) throws Exception
	{
		KeyPair keyPair = Ed25519Signer.newKeyPair();
		byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);

		IllegalArgumentException onSign = assertThrows(IllegalArgumentException.class,
			() -> Signatures.sign(suite, keyPair.getPrivate(), payload));
		IllegalArgumentException onVerify = assertThrows(IllegalArgumentException.class,
			() -> Signatures.verify(suite, keyPair.getPublic(), payload, new byte[64]));

		assertTrue(onSign.getMessage().contains("'" + suite + "'"), onSign.getMessage());
		assertTrue(onVerify.getMessage().contains("'" + suite + "'"), onVerify.getMessage());
	}

	/** A missing suite is a programming error and fails as one, before any key is touched. */
	@ParameterizedTest
	@NullSource
	void aNullSuiteIsRefused(String suite) throws Exception
	{
		KeyPair keyPair = Ed25519Signer.newKeyPair();

		assertThrows(NullPointerException.class,
			() -> Signatures.sign(suite, keyPair.getPrivate(), new byte[1]));
		assertThrows(NullPointerException.class,
			() -> Signatures.verify(suite, keyPair.getPublic(), new byte[1], new byte[64]));
	}

	/**
	 * A signature made under one suite does not verify under another suite with an unrelated key:
	 * the dispatch uses the suite it is given, not whatever the key happens to be.
	 */
	@Test
	void aSignatureDoesNotVerifyUnderAnotherSuite() throws Exception
	{
		KeyPair ed25519 = newKeyPair("Ed25519");
		KeyPair mlDsa = newKeyPair("ML-DSA-44");
		byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);
		byte[] signature = Signatures.sign("Ed25519", ed25519.getPrivate(), payload);

		assertFalse(Signatures.verify("ML-DSA-44", mlDsa.getPublic(), payload, signature));
	}

	/** A fresh key pair for the given suite, generated at test time. */
	static KeyPair newKeyPair(String suite) throws Exception
	{
		if ("Ed25519".equalsIgnoreCase(suite))
		{
			return Ed25519Signer.newKeyPair();
		}
		String keyAlgorithm = Signatures.keyFactoryAlgorithm(suite);
		if (Signatures.isClassical(suite))
		{
			KeyPairGenerator generator = KeyPairGenerator.getInstance(keyAlgorithm);
			generator.initialize("EC".equals(keyAlgorithm) ? 256 : 2048);
			return generator.generateKeyPair();
		}
		KeyPairGeneratorAlgorithm parsed = KeyPairGeneratorAlgorithm
			.valueOf(suite.toUpperCase().replace('-', '_'));
		return parsed.name().startsWith("ML_DSA")
			? MlDsaSigner.newKeyPair(parsed)
			: SlhDsaSigner.newKeyPair(parsed);
	}
}
