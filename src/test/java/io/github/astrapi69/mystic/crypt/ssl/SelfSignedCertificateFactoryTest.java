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
package io.github.astrapi69.mystic.crypt.ssl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Unit tests for the parts of {@link SelfSignedCertificateFactory} that a caller can get wrong
 * before a certificate is ever built.
 */
class SelfSignedCertificateFactoryTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	private static KeyPair keyPair(String algorithm) throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
		generator.initialize(2048);
		return generator.generateKeyPair();
	}

	/**
	 * Both spellings of a PSS signature satisfy RFC 4055: the ...andMGF1 names and a name that says
	 * PSS outright.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "SHA256withRSAandMGF1", "SHA512withRSAandMGF1", "RSASSA-PSS",
			"SHA256WITHRSASSA-PSS" })
	void aPssSignatureIsAcceptedForAnRsassaPssKey(String signatureAlgorithm) throws Exception
	{
		KeyPair keyPair = keyPair("RSASSA-PSS");

		SelfSignedCertificateFactory.requireSignatureFitsTheKey(keyPair, signatureAlgorithm);
	}

	@Test
	void aPlainRsaSignatureIsRefusedForAnRsassaPssKey() throws Exception
	{
		KeyPair keyPair = keyPair("RSASSA-PSS");

		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> SelfSignedCertificateFactory.requireSignatureFitsTheKey(keyPair,
				"SHA256withRSA"));

		assertTrue(rejected.getMessage().contains("RFC 4055"),
			"the message must cite the requirement, but was: '" + rejected.getMessage() + "'");
	}

	@Test
	void aPlainRsaKeyIsNotHeldToThePssRequirement() throws Exception
	{
		SelfSignedCertificateFactory.requireSignatureFitsTheKey(keyPair("RSA"), "SHA256withRSA");
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "example.org", ":example.org", "dns:" })
	void aSubjectAlternativeNameWithoutBothHalvesIsRefusedWithAnExample(String text)
	{
		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> SelfSignedCertificateFactory.SubjectAlternativeName.parse(text));

		assertTrue(rejected.getMessage().contains("dns:example.org"),
			"the message must show what one looks like, but was: '" + rejected.getMessage() + "'");
	}

	@Test
	void anUnknownKeyUsageIsNamedWithTheOnesThatExist()
	{
		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> SelfSignedCertificateFactory.keyUsageBits(java.util.List.of("signEverything")));

		assertTrue(rejected.getMessage().contains("is not a key usage"),
			"the message was: '" + rejected.getMessage() + "'");
	}

	@Test
	void contentCommitmentIsTheOtherNameForNonRepudiation()
	{
		assertEquals(SelfSignedCertificateFactory.keyUsageBits(java.util.List.of("nonRepudiation")),
			SelfSignedCertificateFactory.keyUsageBits(java.util.List.of("contentCommitment")),
			"the two names must select the same bit");
	}
}
