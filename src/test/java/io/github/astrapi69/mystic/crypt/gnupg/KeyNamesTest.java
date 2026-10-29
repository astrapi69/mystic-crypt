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
package io.github.astrapi69.mystic.crypt.gnupg;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.DSAPublicBCPGKey;
import org.bouncycastle.bcpg.ECDSAPublicBCPGKey;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * The names of algorithms gpg does not write in the tests that let gpg write a home: a key whose
 * algorithm the reader does not name, and curves beyond the ones gpg generates there. The public
 * keys are built directly; only their public parameters matter for a name
 */
class KeyNamesTest
{

	@Test
	@DisplayName("an algorithm without a name is given by its OpenPGP number")
	void algorithmOf_anUnnamedAlgorithm_isItsNumber() throws Exception
	{
		BCPGKey dsa = new DSAPublicBCPGKey(BigInteger.valueOf(23), BigInteger.valueOf(11),
			BigInteger.valueOf(4), BigInteger.valueOf(9));

		assertEquals("algorithm 17",
			KeyNames.algorithmOf(publicKey(PublicKeyAlgorithmTags.DSA, dsa)));
	}

	@ParameterizedTest(name = "{0}: {1}")
	@CsvSource({ "1.3.36.3.3.2.8.1.1.7, brainpoolP256r1", "1.3.132.0.10, secp256k1",
			"1.2.840.10045.3.1.7, nistp256", "1.3.132.0.35, nistp521", "1.2.3.4.5, 1.2.3.4.5" })
	@DisplayName("a curve is named as gpg names it, and by its identifier when nobody names it")
	void algorithmOf_aCurve_isNamedAsGpgNamesIt(final String curve, final String expected)
		throws Exception
	{
		BCPGKey ecdsa = new ECDSAPublicBCPGKey(new ASN1ObjectIdentifier(curve),
			BigInteger.valueOf(4));

		assertEquals(expected,
			KeyNames.algorithmOf(publicKey(PublicKeyAlgorithmTags.ECDSA, ecdsa)));
	}

	@Test
	@DisplayName("a key whose self signature states no use has none")
	void usageOf_noKeyFlags_isEmpty()
	{
		assertEquals("", KeyNames.usageOf(null));
	}

	@Test
	@DisplayName("a key whose public part the reader does not match cannot be told here or offline")
	void secretPartOf_anUnmatchedAlgorithm_isUnknown() throws IOException
	{
		BCPGKey dsa = new DSAPublicBCPGKey(BigInteger.valueOf(23), BigInteger.valueOf(11),
			BigInteger.valueOf(4), BigInteger.valueOf(9));

		assertEquals(SecretPart.UNKNOWN,
			SecretKeyFiles.in(java.nio.file.Path.of("no-such-directory")).of(dsa));
	}

	private static PGPPublicKey publicKey(final int algorithm, final BCPGKey key)
		throws PGPException
	{
		return new PGPPublicKey(
			new PublicKeyPacket(PublicKeyPacket.VERSION_4, algorithm, new Date(0), key),
			new BcKeyFingerprintCalculator());
	}
}
