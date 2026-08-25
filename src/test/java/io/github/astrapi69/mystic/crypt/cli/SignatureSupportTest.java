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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Unit tests for the {@link SignatureSupport} helper that hides the split between the Ed25519,
 * ML-DSA and SLH-DSA signer families behind one string-keyed API.
 */
class SignatureSupportTest
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
		assertTrue(SignatureSupport.isEd25519(name));
		assertEquals("Ed25519", SignatureSupport.keyFactoryAlgorithm(name));
	}

	@Test
	void otherAlgorithmNamesAreNotEd25519()
	{
		assertFalse(SignatureSupport.isEd25519("ML-DSA-65"));
	}

	/** The key factory algorithm is the JCA name of the parameter set, dashes included. */
	@ParameterizedTest
	@CsvSource({ "ML-DSA-44, ML-DSA-44", "ml_dsa_65, ML-DSA-65", "ML_DSA_87, ML-DSA-87",
			"SLH-DSA-SHA2-128S, SLH-DSA-SHA2-128S", "slh_dsa_shake_128f, SLH-DSA-SHAKE-128F" })
	void keyFactoryAlgorithmIsTheJcaNameOfTheParameterSet(String input, String expected)
	{
		assertEquals(expected, SignatureSupport.keyFactoryAlgorithm(input));
	}

	/** Algorithms that exist but cannot sign are rejected with a clear message. */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "EC", "DSA", "X25519", "X448", "ML-KEM-512", "ML-KEM-768",
			"ML-KEM-1024" })
	void nonSignatureAlgorithmsAreRejected(String name)
	{
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
			() -> SignatureSupport.keyFactoryAlgorithm(name));
		assertTrue(exception.getMessage().contains("is not a supported signature algorithm"),
			"the message must say why '" + name + "' is rejected, but was: '"
				+ exception.getMessage() + "'");
	}

	@Test
	void unknownAlgorithmNamesAreRejected()
	{
		assertThrows(IllegalArgumentException.class,
			() -> SignatureSupport.keyFactoryAlgorithm("NOPE"));
	}

	/** The sign and verify dispatch must pick the family that belongs to the algorithm name. */
	@ParameterizedTest
	@ValueSource(strings = { "Ed25519", "ML-DSA-65", "SLH-DSA-SHA2-128F" })
	void signAndVerifyRoundTripInEveryFamily(String algorithm) throws Exception
	{
		KeyPair keyPair = SignCommandTest.newKeyPair(algorithm);
		byte[] data = ("round trip " + algorithm).getBytes(StandardCharsets.UTF_8);
		byte[] signature = SignatureSupport.sign(algorithm, keyPair.getPrivate(), data);
		assertTrue(SignatureSupport.verify(algorithm, keyPair.getPublic(), data, signature));
		assertFalse(SignatureSupport.verify(algorithm, keyPair.getPublic(), "other data".getBytes(),
			signature), "the signature must not verify against different data");
	}
}
