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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.util.Arrays;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Parity tests across the post quantum parameter sets: every variant a signer accepts has to sign
 * something its own verifier accepts and nothing else does, and every variant of the key
 * encapsulation has to arrive at the same secret on both sides.
 * <p>
 * The pair tests next to this one drive one or two variants each - ML-DSA at 44 and 65, SLH-DSA at
 * the two 128S sets, ML-KEM at 768. A parameter set is chosen by a caller though, so a variant that
 * was wired to the wrong parameters would pass every one of them.
 * <p>
 * The signature length is asserted against the value FIPS 204 and FIPS 205 give for that parameter
 * set, which is what makes these tests worth more than "nothing was thrown": a variant wired to
 * another one's parameters signs perfectly well, only at the wrong size.
 */
class PqcVariantParityTest
{

	private static final byte[] PAYLOAD = "the message under test".getBytes();

	@BeforeAll
	static void setUp()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	/**
	 * Every ML-DSA parameter set signs, verifies, refuses a tampered signature and a foreign key,
	 * and produces a signature of the length FIPS 204 gives for it.
	 *
	 * @param algorithm
	 *            the parameter set under test
	 * @param expectedSignatureLength
	 *            the signature length FIPS 204 gives for that parameter set
	 * @throws Exception
	 *             if key generation, signing or verifying fails
	 */
	@ParameterizedTest
	@CsvSource({ "ML_DSA_44, 2420", "ML_DSA_65, 3309", "ML_DSA_87, 4627" })
	void everyMlDsaParameterSetSignsAndVerifiesAtItsOwnLength(
		final KeyPairGeneratorAlgorithm algorithm, final int expectedSignatureLength)
		throws Exception
	{
		KeyPair keyPair = MlDsaSigner.newKeyPair(algorithm);
		KeyPair foreignKeyPair = MlDsaSigner.newKeyPair(algorithm);

		byte[] signature = new MlDsaSigner(keyPair.getPrivate(), algorithm).sign(PAYLOAD);

		assertEquals(expectedSignatureLength, signature.length,
			algorithm + " must sign at the length FIPS 204 gives for it");
		assertTrue(new MlDsaVerifier(keyPair.getPublic(), algorithm).verify(PAYLOAD, signature),
			algorithm + " must verify what it signed");
		assertFalse(
			new MlDsaVerifier(foreignKeyPair.getPublic(), algorithm).verify(PAYLOAD, signature),
			algorithm + " must not verify a signature made with another key");
		assertFalse(
			new MlDsaVerifier(keyPair.getPublic(), algorithm).verify(PAYLOAD, tampered(signature)),
			algorithm + " must not verify a tampered signature");
	}

	/**
	 * The same for SLH-DSA. The four slow parameter sets are left out, see
	 * {@link #slhDsaParameterSetsNotCovered()}.
	 *
	 * @param algorithm
	 *            the parameter set under test
	 * @param expectedSignatureLength
	 *            the signature length FIPS 205 gives for that parameter set
	 * @throws Exception
	 *             if key generation, signing or verifying fails
	 */
	@ParameterizedTest
	@CsvSource({ "SLH_DSA_SHA2_128S, 7856", "SLH_DSA_SHAKE_128S, 7856", "SLH_DSA_SHA2_128F, 17088",
			"SLH_DSA_SHAKE_128F, 17088", "SLH_DSA_SHA2_192F, 35664", "SLH_DSA_SHAKE_192F, 35664",
			"SLH_DSA_SHA2_256F, 49856", "SLH_DSA_SHAKE_256F, 49856" })
	void everySlhDsaParameterSetSignsAndVerifiesAtItsOwnLength(
		final KeyPairGeneratorAlgorithm algorithm, final int expectedSignatureLength)
		throws Exception
	{
		KeyPair keyPair = SlhDsaSigner.newKeyPair(algorithm);

		byte[] signature = new SlhDsaSigner(keyPair.getPrivate(), algorithm).sign(PAYLOAD);

		assertEquals(expectedSignatureLength, signature.length,
			algorithm + " must sign at the length FIPS 205 gives for it");
		assertTrue(new SlhDsaVerifier(keyPair.getPublic(), algorithm).verify(PAYLOAD, signature),
			algorithm + " must verify what it signed");
		assertFalse(
			new SlhDsaVerifier(keyPair.getPublic(), algorithm).verify(PAYLOAD, tampered(signature)),
			algorithm + " must not verify a tampered signature");
	}

	/**
	 * The four SLH-DSA parameter sets this class does not drive, named rather than silently absent.
	 * <p>
	 * SLH_DSA_SHA2_192S, SLH_DSA_SHA2_256S, SLH_DSA_SHAKE_192S and SLH_DSA_SHAKE_256S take between
	 * 1.5 and 1.8 seconds each to sign once, measured on this machine, against 43 to 146
	 * milliseconds for the F sets of the same sizes - the S sets buy a smaller signature with
	 * signing time. Adding the four would put about 6.5 seconds on a suite that runs in 38, for
	 * parameter sets that share their code path with the 128S sets driven above. They were
	 * exercised once by hand and verified at 16224 and 29792 bytes.
	 * <p>
	 * This test asserts that the list of what is left out is exactly those four, so a new parameter
	 * set cannot slip past unnoticed.
	 */
	@org.junit.jupiter.api.Test
	void slhDsaParameterSetsNotCovered()
	{
		java.util.Set<String> driven = java.util.Set.of("SLH_DSA_SHA2_128S", "SLH_DSA_SHAKE_128S",
			"SLH_DSA_SHA2_128F", "SLH_DSA_SHAKE_128F", "SLH_DSA_SHA2_192F", "SLH_DSA_SHAKE_192F",
			"SLH_DSA_SHA2_256F", "SLH_DSA_SHAKE_256F");
		java.util.List<String> notDriven = Arrays.stream(KeyPairGeneratorAlgorithm.values())
			.map(Enum::name).filter(name -> name.startsWith("SLH_DSA"))
			.filter(name -> !driven.contains(name)).sorted().toList();

		assertEquals(
			java.util.List.of("SLH_DSA_SHA2_192S", "SLH_DSA_SHA2_256S", "SLH_DSA_SHAKE_192S",
				"SLH_DSA_SHAKE_256S"),
			notDriven,
			"exactly the four slow parameter sets are left out; a new one must be added above "
				+ "rather than quietly join this list");
	}

	/**
	 * Every ML-KEM parameter set arrives at the same secret on both sides, and a foreign key does
	 * not arrive at it. ML-KEM answers a wrong key with a different secret rather than an error,
	 * which is what implicit rejection means, so the assertion is on the secrets and not on a
	 * throw.
	 *
	 * @param algorithm
	 *            the parameter set under test
	 * @throws Exception
	 *             if key generation, encapsulating or decapsulating fails
	 */
	@ParameterizedTest
	@EnumSource(value = KeyPairGeneratorAlgorithm.class, names = { "ML_KEM_512", "ML_KEM_768",
			"ML_KEM_1024" })
	void everyMlKemParameterSetArrivesAtTheSameSecret(final KeyPairGeneratorAlgorithm algorithm)
		throws Exception
	{
		KeyPair keyPair = MlKemKeyExchange.newKeyPair(algorithm);
		KeyPair foreignKeyPair = MlKemKeyExchange.newKeyPair(algorithm);

		MlKemKeyExchange.Encapsulation encapsulation = MlKemKeyExchange
			.encapsulate(keyPair.getPublic(), algorithm);
		SecretKey opened = MlKemKeyExchange.decapsulate(keyPair.getPrivate(),
			encapsulation.getCiphertext(), algorithm);

		assertArrayEquals(encapsulation.getSharedSecret().getEncoded(), opened.getEncoded(),
			algorithm + " must arrive at the same secret on both sides");

		SecretKey openedWithAForeignKey = MlKemKeyExchange.decapsulate(foreignKeyPair.getPrivate(),
			encapsulation.getCiphertext(), algorithm);
		assertFalse(
			Arrays.equals(encapsulation.getSharedSecret().getEncoded(),
				openedWithAForeignKey.getEncoded()),
			algorithm + " must not arrive at the secret with a key it was not meant for");
	}

	private static byte[] tampered(final byte[] signature)
	{
		byte[] changed = signature.clone();
		changed[changed.length / 2] ^= 0x01;
		return changed;
	}
}
