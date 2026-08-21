/**
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
package io.github.astrapi69.mystic.crypt.srp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link SRP6aVerifierGenerator}.
 */
class SRP6aVerifierGeneratorTest
{

	@Test
	void testConstructorWithDefaults()
	{
		final SRP6aVerifierGenerator generator = new SRP6aVerifierGenerator();

		assertNotNull(generator.getN());
		assertNotNull(generator.getG());
		assertEquals("SHA-256", generator.getHashAlgorithm());
	}

	@Test
	void testConstructorWithCustomParameters()
	{
		final BigInteger customN = new BigInteger("1000000000000000000000000000000000000000000000000000000000000000");
		final BigInteger customG = BigInteger.valueOf(3);

		final SRP6aVerifierGenerator generator = new SRP6aVerifierGenerator(customN, customG,
			"SHA-512");

		assertEquals(customN, generator.getN());
		assertEquals(customG, generator.getG());
		assertEquals("SHA-512", generator.getHashAlgorithm());
	}

	@Test
	void testConstructorWithNullParameters()
	{
		assertThrows(IllegalArgumentException.class, () -> {
			new SRP6aVerifierGenerator(null, BigInteger.valueOf(2), "SHA-256");
		});

		assertThrows(IllegalArgumentException.class, () -> {
			new SRP6aVerifierGenerator(BigInteger.TEN, null, "SHA-256");
		});

		assertThrows(IllegalArgumentException.class, () -> {
			new SRP6aVerifierGenerator(BigInteger.TEN, BigInteger.valueOf(2), null);
		});
	}

	@Test
	void testGenerateSalt()
	{
		final SRP6aVerifierGenerator generator = new SRP6aVerifierGenerator();

		final byte[] salt1 = generator.generateSalt();
		final byte[] salt2 = generator.generateSalt();

		assertNotNull(salt1);
		assertNotNull(salt2);
		assertEquals(16, salt1.length);
		assertEquals(16, salt2.length);

		assertTrue(!java.util.Arrays.equals(salt1, salt2));
	}

	@Test
	void testGenerateVerifier()
	{
		final SRP6aVerifierGenerator generator = new SRP6aVerifierGenerator();
		final String identity = "testuser";
		final char[] password = "testPassword123".toCharArray();
		final byte[] salt = generator.generateSalt();

		final BigInteger verifier = generator.generateVerifier(identity, password, salt);

		assertNotNull(verifier);
		assertTrue(verifier.compareTo(BigInteger.ZERO) > 0);
		assertTrue(verifier.compareTo(generator.getN()) < 0);
	}

	@Test
	void testGenerateVerifierWithNullIdentity()
	{
		final SRP6aVerifierGenerator generator = new SRP6aVerifierGenerator();
		final char[] password = "testPassword123".toCharArray();
		final byte[] salt = generator.generateSalt();

		assertThrows(IllegalArgumentException.class, () -> {
			generator.generateVerifier(null, password, salt);
		});
	}

	@Test
	void testGenerateVerifierWithNullPassword()
	{
		final SRP6aVerifierGenerator generator = new SRP6aVerifierGenerator();
		final String identity = "testuser";
		final byte[] salt = generator.generateSalt();

		assertThrows(IllegalArgumentException.class, () -> {
			generator.generateVerifier(identity, null, salt);
		});
	}

	@Test
	void testGenerateVerifierWithNullSalt()
	{
		final SRP6aVerifierGenerator generator = new SRP6aVerifierGenerator();
		final String identity = "testuser";
		final char[] password = "testPassword123".toCharArray();

		assertThrows(IllegalArgumentException.class, () -> {
			generator.generateVerifier(identity, password, null);
		});
	}

	@Test
	void testSameCredentialsProduceSameVerifier()
	{
		final SRP6aVerifierGenerator generator = new SRP6aVerifierGenerator();
		final String identity = "testuser";
		final char[] password = "testPassword123".toCharArray();
		final byte[] salt = new byte[16];
		java.security.SecureRandom random = new java.security.SecureRandom();
		random.nextBytes(salt);

		final BigInteger verifier1 = generator.generateVerifier(identity, password.clone(), salt);
		final BigInteger verifier2 = generator.generateVerifier(identity, password.clone(), salt);

		assertEquals(verifier1, verifier2);
	}

	@Test
	void testDifferentPasswordsProduceDifferentVerifiers()
	{
		final SRP6aVerifierGenerator generator = new SRP6aVerifierGenerator();
		final String identity = "testuser";
		final byte[] salt = new byte[16];
		java.security.SecureRandom random = new java.security.SecureRandom();
		random.nextBytes(salt);

		final char[] password1 = "password1".toCharArray();
		final char[] password2 = "password2".toCharArray();

		final BigInteger verifier1 = generator.generateVerifier(identity, password1, salt);
		final BigInteger verifier2 = generator.generateVerifier(identity, password2, salt);

		assertTrue(!verifier1.equals(verifier2));
	}

	@Test
	void testDifferentSaltsProduceDifferentVerifiers()
	{
		final SRP6aVerifierGenerator generator = new SRP6aVerifierGenerator();
		final String identity = "testuser";
		final char[] password = "testPassword123".toCharArray();

		final byte[] salt1 = generator.generateSalt();
		final byte[] salt2 = generator.generateSalt();

		final BigInteger verifier1 = generator.generateVerifier(identity, password.clone(), salt1);
		final BigInteger verifier2 = generator.generateVerifier(identity, password.clone(), salt2);

		assertTrue(!verifier1.equals(verifier2));
	}

}
