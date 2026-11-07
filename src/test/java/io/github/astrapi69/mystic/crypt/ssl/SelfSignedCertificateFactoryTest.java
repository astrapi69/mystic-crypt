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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
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

	/**
	 * RFC 5280 section 4.1.2.2: the serial number is a positive integer of at most 20 octets, and
	 * two certificates of one issuer do not share one (#253)
	 */
	@Test
	void theSerialNumberIsPositive_fitsInto20Octets_andDiffersBetweenTwoCertificates()
		throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(256);
		KeyPair keyPair = generator.generateKeyPair();
		X500Name name = new X500Name("CN=serial");
		SelfSignedCertificateFactory.Extensions noExtensions = new SelfSignedCertificateFactory.Extensions(
			null, List.of(), List.of(), List.of());

		BigInteger first = SelfSignedCertificateFactory
			.create(keyPair, name, 1, "SHA256withECDSA", noExtensions).getSerialNumber();
		BigInteger second = SelfSignedCertificateFactory
			.create(keyPair, name, 1, "SHA256withECDSA", noExtensions).getSerialNumber();

		for (BigInteger serialNumber : List.of(first, second))
		{
			assertEquals(1, serialNumber.signum(), "positive: " + serialNumber);
			// toByteArray is the content of the DER INTEGER, sign byte included
			assertTrue(serialNumber.toByteArray().length <= 20, "20 octets: " + serialNumber);
		}
		assertNotEquals(first, second);
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

	/**
	 * The colon has to sit at position one at the earliest - a one character type is still a type -
	 * and the value after it must not be empty.
	 */
	@Test
	void aOneCharacterTypeIsStillAType()
	{
		SelfSignedCertificateFactory.SubjectAlternativeName name = SelfSignedCertificateFactory.SubjectAlternativeName
			.parse("d:x");

		assertEquals("d", name.type());
		assertEquals("x", name.value());
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
