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
package io.github.astrapi69.mystic.crypt.pw;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Unit tests for {@link ScryptSupport}, the PHC-like encoding that lets a scrypt hash be verified
 * from the stored string alone.
 */
class ScryptSupportTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	@Test
	void aPasswordVerifiesAgainstItsOwnHashAndNothingElse()
	{
		String encoded = ScryptSupport.hash("the-secret".toCharArray());

		assertTrue(encoded.startsWith(ScryptSupport.PREFIX));
		assertTrue(ScryptSupport.verify("the-secret".toCharArray(), encoded));
		assertFalse(ScryptSupport.verify("not-the-secret".toCharArray(), encoded));
	}

	@Test
	void theParametersTravelWithTheHashSoTheyNeedNotBeStoredElsewhere()
	{
		String encoded = ScryptSupport.hash("the-secret".toCharArray());

		assertTrue(encoded.contains("ln=" + ScryptSupport.DEFAULT_LOG_N),
			"the cost must be readable from the hash, but was: '" + encoded + "'");
		assertTrue(encoded.contains("r=" + ScryptSupport.DEFAULT_R));
		assertTrue(encoded.contains("p=" + ScryptSupport.DEFAULT_P));
		assertEquals(5, encoded.split("\\$").length,
			"the encoding is $scrypt$params$salt$hash, but was: '" + encoded + "'");
	}

	@Test
	void aFreshSaltPerCallMakesTwoHashesOfTheSamePasswordDiffer()
	{
		assertNotEquals(ScryptSupport.hash("same".toCharArray()),
			ScryptSupport.hash("same".toCharArray()));
	}

	/**
	 * Every one of these is malformed in a different way, and each must come back as "does not
	 * match" rather than as an exception out of the hasher.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "", "not a hash at all", "$scrypt$",
			"$argon2id$v=19$m=1,t=1,p=1$AA$BB", "$scrypt$ln=15,r=8$AA$BB",
			"$scrypt$ln=15,r=8,p=1,x=2$AA$BB", "$scrypt$lnr8p1$AA$BB", "$scrypt$ln=0,r=8,p=1$AA$BB",
			"$scrypt$ln=31,r=8,p=1$AA$BB", "$scrypt$ln=15,r=0,p=1$AA$BB",
			"$scrypt$ln=15,r=8,p=0$AA$BB", "$scrypt$ln=notanumber,r=8,p=1$AA$BB",
			"$scrypt$ln=15,r=8,p=1$not base64$BB", "$bogus$ln=15,r=8,p=1$AA$BB" })
	void aMalformedHashAnswersFalseRatherThanThrowing(String encoded)
	{
		assertFalse(ScryptSupport.verify("whatever".toCharArray(), encoded),
			"a malformed hash must answer false, but '" + encoded + "' did not");
	}

	@Test
	void theZeroCostBoundIsRefusedBecauseItWouldOverflowIntoANegativeN()
	{
		// 1 << 31 is negative, which the hasher would reject with an exception rather than a
		// "does not match"; the upper bound on ln is what keeps that out of the hasher
		assertFalse(ScryptSupport.verify("whatever".toCharArray(), "$scrypt$ln=31,r=8,p=1$AA$BB"));
		assertFalse(ScryptSupport.verify("whatever".toCharArray(), "$scrypt$ln=99,r=8,p=1$AA$BB"));
	}

	@Test
	void thePasswordArrayIsClearedOnBothPaths()
	{
		char[] toHash = "wipe me".toCharArray();
		String encoded = ScryptSupport.hash(toHash);
		assertArrayEquals(new char[toHash.length], toHash,
			"hash must zero the password it was given");

		char[] toVerify = "wipe me".toCharArray();
		ScryptSupport.verify(toVerify, encoded);
		assertArrayEquals(new char[toVerify.length], toVerify,
			"verify must zero the password it was given");
	}

	@Test
	void anEncodingOfNoKnownAlgorithmIsNamedWithTheOnesThatAre()
	{
		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> PasswordHashFormat.of(null));

		assertTrue(rejected.getMessage().contains("$scrypt$"),
			"the message must list the encodings, but was: '" + rejected.getMessage() + "'");
	}

	@Test
	void nullIsRefusedOutright()
	{
		assertThrows(NullPointerException.class, () -> ScryptSupport.hash(null));
		assertThrows(NullPointerException.class,
			() -> ScryptSupport.verify(null, "$scrypt$ln=15,r=8,p=1$AA$BB"));
		assertThrows(NullPointerException.class,
			() -> ScryptSupport.verify("x".toCharArray(), null));
	}
}
