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
package io.github.astrapi69.mystic.crypt.sha;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

/**
 * Mutation-focused tests for the hasher classes: boundary conditions that must be
 * <em>accepted</em>, secure-wipe of caller supplied password arrays, random-salt behaviour and the
 * delegating hash overloads. These complement {@link HasherArgumentValidationTest} which only
 * covers the reject paths.
 */
class HasherBoundaryAndWipeTest
{

	private static final byte[] DATA = "the quick brown fox".getBytes(StandardCharsets.UTF_8);

	private static char[] pw()
	{
		return "correct horse battery staple".toCharArray();
	}

	private static boolean allZero(char[] array)
	{
		for (char c : array)
		{
			if (c != '\0')
			{
				return false;
			}
		}
		return true;
	}

	// ----- BCrypt -----------------------------------------------------------

	@Test
	void bcryptAcceptsMinimumLogRounds()
	{
		// kills the "< MIN_LOG_ROUNDS" boundary mutant: MIN itself must be accepted
		String hash = BcryptHasher.hash(pw(), BcryptHasher.MIN_LOG_ROUNDS);
		assertNotNull(hash);
		assertEquals(BcryptHasher.MIN_LOG_ROUNDS, BcryptHasher.getLogRounds(hash));

		byte[] salt = new byte[16];
		String saltedHash = BcryptHasher.hashWithSalt(pw(), salt, BcryptHasher.MIN_LOG_ROUNDS);
		assertNotNull(saltedHash);
		assertEquals(BcryptHasher.MIN_LOG_ROUNDS, BcryptHasher.getLogRounds(saltedHash));
	}

	@Test
	void bcryptHashUsesAFreshRandomSaltEveryTime()
	{
		// kills the removed SecureRandom.nextBytes(salt) call: without it the salt is all
		// zero and two hashes of the same password would be identical
		String first = BcryptHasher.hash(pw(), BcryptHasher.MIN_LOG_ROUNDS);
		String second = BcryptHasher.hash(pw(), BcryptHasher.MIN_LOG_ROUNDS);
		assertNotEquals(first, second);
	}

	@Test
	void bcryptHashWithSaltWipesThePassword()
	{
		// kills the removed Arrays.fill(password, '\0') call in hashWithSalt
		char[] password = pw();
		BcryptHasher.hashWithSalt(password, new byte[16], BcryptHasher.MIN_LOG_ROUNDS);
		assertTrue(allZero(password), "password array must be wiped after hashWithSalt");
	}

	@Test
	void bcryptVerifyWipesThePasswordAndReturnsCorrectResult()
	{
		// kills the removed Arrays.fill(password, '\0') call in verify
		String hash = BcryptHasher.hash(pw(), BcryptHasher.MIN_LOG_ROUNDS);
		char[] password = pw();
		assertTrue(BcryptHasher.verify(password, hash));
		assertTrue(allZero(password), "password array must be wiped after verify");

		char[] wrong = "wrong password".toCharArray();
		assertFalse(BcryptHasher.verify(wrong, hash));
	}

	// ----- SCrypt -----------------------------------------------------------

	@Test
	void scryptHashRejectsNonPowerOfTwoNParameter()
	{
		// kills the removed validateParameters call in hash and the "return true" mutant of
		// isPowerOfTwo: N = 3 is >= MIN_N but not a power of two and must be rejected with our
		// specific message
		IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
			() -> ScryptHasher.hash(pw(), 3, ScryptHasher.MIN_R, ScryptHasher.MIN_P));
		assertEquals("N must be a power of 2 and at least " + ScryptHasher.MIN_N, ex.getMessage());
	}

	@Test
	void scryptVerifyRejectsNonPowerOfTwoNParameter()
	{
		// kills the removed validateParameters call in verify
		IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
			() -> ScryptHasher.verify(pw(), new byte[ScryptHasher.SALT_LENGTH], new byte[32], 3,
				ScryptHasher.MIN_R, ScryptHasher.MIN_P));
		assertEquals("N must be a power of 2 and at least " + ScryptHasher.MIN_N, ex.getMessage());
	}

	@Test
	void scryptHashUsesAFreshRandomSaltEveryTime()
	{
		// kills the removed SecureRandom.nextBytes(salt) call in generateSalt: without it the salt
		// is all zero and two hashes of the same password would be identical
		byte[] first = ScryptHasher.hash(pw());
		byte[] second = ScryptHasher.hash(pw());
		assertFalse(java.util.Arrays.equals(first, second));
	}

	@Test
	void scryptHashWithSaltWipesThePassword()
	{
		// kills the removed Arrays.fill(password, '\0') call in hashWithSalt
		char[] password = pw();
		ScryptHasher.hashWithSalt(password, new byte[ScryptHasher.SALT_LENGTH], ScryptHasher.MIN_N,
			ScryptHasher.MIN_R, ScryptHasher.MIN_P, 32);
		assertTrue(allZero(password), "password array must be wiped after hashWithSalt");
	}

	@Test
	void scryptVerifyWipesThePasswordAndReturnsCorrectResult()
	{
		// kills the removed Arrays.fill(password, '\0') call in verify
		byte[] salt = new byte[ScryptHasher.SALT_LENGTH];
		byte[] expected = ScryptHasher.hashWithSalt(pw(), salt, ScryptHasher.MIN_N,
			ScryptHasher.MIN_R, ScryptHasher.MIN_P, 32);
		char[] password = pw();
		assertTrue(ScryptHasher.verify(password, salt, expected, ScryptHasher.MIN_N,
			ScryptHasher.MIN_R, ScryptHasher.MIN_P));
		assertTrue(allZero(password), "password array must be wiped after verify");

		char[] wrong = "wrong".toCharArray();
		assertFalse(ScryptHasher.verify(wrong, salt, expected, ScryptHasher.MIN_N,
			ScryptHasher.MIN_R, ScryptHasher.MIN_P));
	}

	// ----- BLAKE2b ----------------------------------------------------------

	@Test
	void blake2bAcceptsDigestLengthBoundaries()
	{
		// kills both "changed conditional boundary" mutants on the digest length guard: MIN and
		// MAX must be accepted and produce an output of exactly that length
		assertEquals(Blake2bHasher.MIN_DIGEST_LENGTH,
			Blake2bHasher.hash(DATA, Blake2bHasher.MIN_DIGEST_LENGTH).length);
		assertEquals(Blake2bHasher.MAX_DIGEST_LENGTH,
			Blake2bHasher.hash(DATA, Blake2bHasher.MAX_DIGEST_LENGTH).length);
	}

	@Test
	void blake2bStringHashUsesTheDefaultDigestLength()
	{
		// kills the "replaced return value with null" mutant of hash(String, Charset) and asserts
		// it delegates to the default digest length
		byte[] hash = Blake2bHasher.hash("payload", StandardCharsets.UTF_8);
		assertNotNull(hash);
		assertEquals(Blake2bHasher.DEFAULT_DIGEST_LENGTH, hash.length);
		assertArrayEquals(Blake2bHasher.hash("payload", StandardCharsets.UTF_8,
			Blake2bHasher.DEFAULT_DIGEST_LENGTH), hash);
	}

	@Test
	void blake2bKeyedHashAcceptsBoundaryKeyLengthAndDigestLength()
	{
		// kills the "key.length > 64" boundary mutant: a key of exactly the max length is valid
		byte[] maxKey = new byte[64];
		assertNotNull(Blake2bHasher.hashWithKey(DATA, maxKey, Blake2bHasher.DEFAULT_DIGEST_LENGTH));
		// a key one byte too long must still be rejected
		assertThrows(IllegalArgumentException.class, () -> Blake2bHasher.hashWithKey(DATA,
			new byte[65], Blake2bHasher.DEFAULT_DIGEST_LENGTH));
		// kills both digest length boundary mutants on the keyed overload
		assertEquals(Blake2bHasher.MIN_DIGEST_LENGTH,
			Blake2bHasher.hashWithKey(DATA, maxKey, Blake2bHasher.MIN_DIGEST_LENGTH).length);
		assertEquals(Blake2bHasher.MAX_DIGEST_LENGTH,
			Blake2bHasher.hashWithKey(DATA, maxKey, Blake2bHasher.MAX_DIGEST_LENGTH).length);
	}

	// ----- BLAKE2s ----------------------------------------------------------

	@Test
	void blake2sAcceptsDigestLengthBoundaries()
	{
		assertEquals(Blake2sHasher.MIN_DIGEST_LENGTH,
			Blake2sHasher.hash(DATA, Blake2sHasher.MIN_DIGEST_LENGTH).length);
		assertEquals(Blake2sHasher.MAX_DIGEST_LENGTH,
			Blake2sHasher.hash(DATA, Blake2sHasher.MAX_DIGEST_LENGTH).length);
	}

	@Test
	void blake2sStringHashUsesTheDefaultDigestLength()
	{
		byte[] hash = Blake2sHasher.hash("payload", StandardCharsets.UTF_8);
		assertNotNull(hash);
		assertEquals(Blake2sHasher.DEFAULT_DIGEST_LENGTH, hash.length);
		assertArrayEquals(Blake2sHasher.hash("payload", StandardCharsets.UTF_8,
			Blake2sHasher.DEFAULT_DIGEST_LENGTH), hash);
	}

	@Test
	void blake2sKeyedHashAcceptsBoundaryKeyLengthAndDigestLength()
	{
		byte[] maxKey = new byte[32];
		assertNotNull(Blake2sHasher.hashWithKey(DATA, maxKey, Blake2sHasher.DEFAULT_DIGEST_LENGTH));
		assertThrows(IllegalArgumentException.class, () -> Blake2sHasher.hashWithKey(DATA,
			new byte[33], Blake2sHasher.DEFAULT_DIGEST_LENGTH));
		assertEquals(Blake2sHasher.MIN_DIGEST_LENGTH,
			Blake2sHasher.hashWithKey(DATA, maxKey, Blake2sHasher.MIN_DIGEST_LENGTH).length);
		assertEquals(Blake2sHasher.MAX_DIGEST_LENGTH,
			Blake2sHasher.hashWithKey(DATA, maxKey, Blake2sHasher.MAX_DIGEST_LENGTH).length);
	}
}
