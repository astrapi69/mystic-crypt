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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Drives every algorithm the enum names through this repository's key writing surface, so that a
 * change in crypt-data is noticed here rather than by a user.
 * <p>
 * The matrix is derived from {@link KeyPairGeneratorAlgorithm#values()} and filtered by what can
 * actually be generated. A filter like that is the quiet way to lose coverage: if a provider stops
 * generating some algorithm, it drops out of every case below and the suite still passes, testing
 * less and saying nothing. {@link #theGeneratableSetIsExactlyTheOneTheseTestsClaimToCover()} is the
 * answer to that - it pins the size and the names, so the set shrinking is a failure and not a
 * silence.
 */
class KeyWritingAcrossAlgorithmsTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	static Stream<KeyPairGeneratorAlgorithm> generatableAlgorithms()
	{
		return Arrays.stream(KeyPairGeneratorAlgorithm.values())
			.filter(KeyWritingAcrossAlgorithmsTest::canGenerate);
	}

	private static boolean canGenerate(final KeyPairGeneratorAlgorithm algorithm)
	{
		try
		{
			newPrivateKey(algorithm);
			return true;
		}
		catch (Exception cannotGenerate)
		{
			return false;
		}
	}

	private static PrivateKey newPrivateKey(final KeyPairGeneratorAlgorithm algorithm)
		throws Exception
	{
		String name = algorithm.getAlgorithm();
		KeyPairGenerator generator = KeyPairGenerator.getInstance(name,
			BouncyCastleProvider.PROVIDER_NAME);
		if ("RSA".equals(name) || "DSA".equals(name) || "RSASSA-PSS".equals(name))
		{
			generator.initialize(2048);
		}
		if ("DiffieHellman".equals(name) || "DH".equals(name))
		{
			generator.initialize(1024);
		}
		return generator.generateKeyPair().getPrivate();
	}

	/**
	 * The guard on the filter above. Without it a provider that stops generating an algorithm takes
	 * that algorithm silently out of every parameterized case in this class, and the run still
	 * reports success. A gate that scans a set has to report the size of the set.
	 */
	@Test
	void theGeneratableSetIsExactlyTheOneTheseTestsClaimToCover()
	{
		List<String> generatable = generatableAlgorithms().map(Enum::name).sorted().toList();
		List<String> refused = new ArrayList<>(
			Arrays.stream(KeyPairGeneratorAlgorithm.values()).map(Enum::name).sorted().toList());
		refused.removeAll(generatable);

		assertEquals(List.of("UNKNOWN", "XDH"), refused,
			"UNKNOWN is not an algorithm and XDH is an umbrella name that needs a curve before a "
				+ "generator will take it; anything else dropping out means the provider changed "
				+ "and these tests quietly cover less than they claim");
		assertEquals(KeyPairGeneratorAlgorithm.values().length - 2, generatable.size(),
			"every other constant must be generatable, was: " + generatable);
	}

	/**
	 * PKCS#8 is the encoding every private key has, so this must hold for the whole matrix.
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @throws Exception
	 *             if the key cannot be generated or written
	 */
	@ParameterizedTest(name = "{0} writes PKCS#8")
	@MethodSource("generatableAlgorithms")
	void everyAlgorithmWritesPkcs8(final KeyPairGeneratorAlgorithm algorithm) throws Exception
	{
		String pem = KeyFileWriter.toPem(newPrivateKey(algorithm), false);

		assertTrue(pem.startsWith("-----BEGIN " + KeyFileWriter.PKCS8_LABEL + "-----"),
			algorithm + " must write the PKCS#8 header, but began: " + firstLine(pem));
	}

	/**
	 * Asking for the traditional form either produces one that names its algorithm in the header,
	 * or falls back to PKCS#8. Which of the two it is has to be readable off the header - that is
	 * what the CLI relies on to refuse a request it cannot honour (#127).
	 *
	 * @param algorithm
	 *            the algorithm under test
	 * @throws Exception
	 *             if the key cannot be generated or written
	 */
	@ParameterizedTest(name = "{0} traditional form is labelled honestly")
	@MethodSource("generatableAlgorithms")
	void theTraditionalFormNamesItselfOrIsPkcs8(final KeyPairGeneratorAlgorithm algorithm)
		throws Exception
	{
		String header = firstLine(KeyFileWriter.toPem(newPrivateKey(algorithm), true));

		assertTrue(header.endsWith(" PRIVATE KEY-----"),
			algorithm + " must write a private key header, but wrote: " + header);
		assertTrue(header.startsWith("-----BEGIN "),
			algorithm + " must write a PEM header, but wrote: " + header);
	}

	/**
	 * Which algorithms have a traditional form is a fact about crypt-data, and this repository
	 * depends on it: the CLI refuses PKCS#1 exactly where there is none (#127). Pinning the set
	 * here means a change on that side fails this build instead of changing what the CLI accepts
	 * without anyone noticing.
	 *
	 * @throws Exception
	 *             if a key cannot be generated or written
	 */
	@Test
	void exactlyFourAlgorithmsHaveATraditionalFormOfTheirOwn() throws Exception
	{
		List<String> traditional = new ArrayList<>();
		for (KeyPairGeneratorAlgorithm algorithm : generatableAlgorithms().toList())
		{
			String header = firstLine(KeyFileWriter.toPem(newPrivateKey(algorithm), true));
			if (!header.equals("-----BEGIN " + KeyFileWriter.PKCS8_LABEL + "-----"))
			{
				traditional.add(algorithm.name());
			}
		}

		assertEquals(List.of("DSA", "EC", "RSA", "RSASSA_PSS"),
			traditional.stream().sorted().toList(),
			"the CLI refuses PKCS#1 outside this set, so the set changing is a change in what the "
				+ "CLI accepts");
	}

	private static String firstLine(final String pem)
	{
		return pem.lines().findFirst().orElse("");
	}
}
