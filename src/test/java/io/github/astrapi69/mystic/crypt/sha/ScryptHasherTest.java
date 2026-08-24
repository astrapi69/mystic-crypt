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
package io.github.astrapi69.mystic.crypt.sha;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ScryptHasher}.
 */
class ScryptHasherTest
{

	@Test
	void testHashWithDefaultParameters()
	{
		final char[] password = "testPassword123".toCharArray();
		final byte[] hash = ScryptHasher.hash(password);

		assertNotNull(hash);
		assertEquals(ScryptHasher.SALT_LENGTH + ScryptHasher.HASH_LENGTH, hash.length);
	}

	@Test
	void testHashWithCustomParameters()
	{
		final char[] password = "testPassword123".toCharArray();
		final byte[] hash = ScryptHasher.hash(password, 1024, 8, 1);

		assertNotNull(hash);
		assertEquals(ScryptHasher.SALT_LENGTH + ScryptHasher.HASH_LENGTH, hash.length);
	}

	@Test
	void testHashConvenienceRoundTripsWithVerify()
	{
		final char[] password = "testPassword123".toCharArray();
		final byte[] saltAndHash = ScryptHasher.hash(password.clone(), 1024, 8, 1);

		assertTrue(ScryptHasher.verify(password, saltAndHash, 1024, 8, 1));
	}

	@Test
	void testHashConvenienceRoundTripFailsForWrongPassword()
	{
		final char[] password = "testPassword123".toCharArray();
		final byte[] saltAndHash = ScryptHasher.hash(password.clone(), 1024, 8, 1);

		final char[] wrongPassword = "wrongPassword".toCharArray();
		assertFalse(ScryptHasher.verify(wrongPassword, saltAndHash, 1024, 8, 1));
	}

	@Test
	void testHashWithInvalidN()
	{
		final char[] password = "testPassword123".toCharArray();

		assertThrows(IllegalArgumentException.class, () -> {
			ScryptHasher.hash(password, 3, 8, 1);
		});

		assertThrows(IllegalArgumentException.class, () -> {
			ScryptHasher.hash(password, 0, 8, 1);
		});

		// N = 1 is a power of two but below MIN_N, exercising the lower-bound arm of the guard that
		// the power-of-two check alone would let through
		assertThrows(IllegalArgumentException.class, () -> {
			ScryptHasher.hash(password, 1, 8, 1);
		});
	}

	@Test
	void testHashWithNullPassword()
	{
		assertThrows(IllegalArgumentException.class, () -> {
			ScryptHasher.hash(null);
		});
	}

	@Test
	void testVerifyCorrectPassword()
	{
		final char[] password = "testPassword123".toCharArray();
		final byte[] salt = new byte[16];
		new java.security.SecureRandom().nextBytes(salt);

		final byte[] hash = ScryptHasher.hashWithSalt(password.clone(), salt, 16384, 8, 1, 32);

		assertTrue(ScryptHasher.verify(password, salt, hash, 16384, 8, 1));
	}

	@Test
	void testVerifyWrongPassword()
	{
		final char[] password = "testPassword123".toCharArray();
		final byte[] salt = new byte[16];
		new java.security.SecureRandom().nextBytes(salt);

		final byte[] hash = ScryptHasher.hashWithSalt(password.clone(), salt, 16384, 8, 1, 32);

		final char[] wrongPassword = "wrongPassword".toCharArray();
		assertFalse(ScryptHasher.verify(wrongPassword, salt, hash, 16384, 8, 1));
	}

	@Test
	void testVerifyWithNullPassword()
	{
		final byte[] salt = new byte[16];
		final byte[] hash = new byte[32];

		assertThrows(IllegalArgumentException.class, () -> {
			ScryptHasher.verify(null, salt, hash, 16384, 8, 1);
		});
	}

	@Test
	void testVerifyWithNullSalt()
	{
		final char[] password = "testPassword123".toCharArray();
		final byte[] hash = new byte[32];

		assertThrows(IllegalArgumentException.class, () -> {
			ScryptHasher.verify(password, null, hash, 16384, 8, 1);
		});
	}

	@Test
	void testHashWithSaltProducesConsistentResults()
	{
		final char[] password = "testPassword123".toCharArray();
		final byte[] salt = new byte[16];
		new java.security.SecureRandom().nextBytes(salt);

		final byte[] hash1 = ScryptHasher.hashWithSalt(password.clone(), salt, 1024, 8, 1, 32);
		final byte[] hash2 = ScryptHasher.hashWithSalt(password.clone(), salt, 1024, 8, 1, 32);

		assertArrayEquals(hash1, hash2);
	}

	@Test
	void testPasswordArrayCleared()
	{
		final char[] password = "testPassword123".toCharArray();
		final char[] originalCopy = password.clone();

		ScryptHasher.hash(password, 1024, 8, 1);

		assertFalse(java.util.Arrays.equals(originalCopy, password));
	}

	@Test
	void testDifferentParametersProduceDifferentHashes()
	{
		final char[] password = "testPassword123".toCharArray();
		final byte[] salt = new byte[16];
		new java.security.SecureRandom().nextBytes(salt);

		final byte[] hash1 = ScryptHasher.hashWithSalt(password.clone(), salt, 1024, 8, 1, 32);
		final byte[] hash2 = ScryptHasher.hashWithSalt(password.clone(), salt, 2048, 8, 1, 32);

		assertFalse(java.util.Arrays.equals(hash1, hash2));
	}

	@Test
	void testHashWithCustomOutputLength()
	{
		final char[] password = "testPassword123".toCharArray();
		final byte[] salt = new byte[16];
		new java.security.SecureRandom().nextBytes(salt);

		final byte[] hash64 = ScryptHasher.hashWithSalt(password.clone(), salt, 1024, 8, 1, 64);
		assertEquals(64, hash64.length);

		final byte[] hash16 = ScryptHasher.hashWithSalt(password.clone(), salt, 1024, 8, 1, 16);
		assertEquals(16, hash16.length);
	}

	/**
	 * Test method for the private {@code isPowerOfTwo(int)} at its zero boundary. Through the
	 * method's only current caller, {@code validateParameters}, the answer at {@code n == 0} does
	 * not matter: {@code !isPowerOfTwo(n) || n < MIN_N} throws either way, because the second
	 * clause independently rejects zero. That redundancy is exactly why a boundary mutant on
	 * {@code isPowerOfTwo} itself survives mutation testing without this test - the primitive's own
	 * contract, "zero is not a power of two", is untested and unenforced if this method is ever
	 * called from anywhere else. Invoked via reflection because the method is private; no
	 * production code changed to make it testable.
	 */
	@Test
	void isPowerOfTwo_answersFalseForZero()
		throws NoSuchMethodException, IllegalAccessException, InvocationTargetException
	{
		final Method isPowerOfTwo = ScryptHasher.class.getDeclaredMethod("isPowerOfTwo", int.class);
		isPowerOfTwo.setAccessible(true);

		assertFalse((boolean)isPowerOfTwo.invoke(null, 0));
	}

}
