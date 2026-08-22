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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link BcryptHasher}.
 */
class BcryptHasherTest
{

	@Test
	void testHashWithDefaultRounds()
	{
		final char[] password = "testPassword123".toCharArray();
		final String hash = BcryptHasher.hash(password);

		assertNotNull(hash);
		assertTrue(hash.startsWith("$2"));
		assertEquals(60, hash.length());
	}

	@Test
	void testHashWithCustomRounds()
	{
		final char[] password = "testPassword123".toCharArray();
		final String hash = BcryptHasher.hash(password, 12);

		assertNotNull(hash);
		assertTrue(hash.startsWith("$2y$12$"));
	}

	@Test
	void testHashWithInvalidRounds()
	{
		final char[] password = "testPassword123".toCharArray();

		assertThrows(IllegalArgumentException.class, () -> {
			BcryptHasher.hash(password, 3);
		});

		assertThrows(IllegalArgumentException.class, () -> {
			BcryptHasher.hash(password, 32);
		});
	}

	@Test
	void testHashWithNullPassword()
	{
		assertThrows(IllegalArgumentException.class, () -> {
			BcryptHasher.hash(null);
		});
	}

	@Test
	void testVerifyCorrectPassword()
	{
		final char[] password = "testPassword123".toCharArray();
		final String hash = BcryptHasher.hash(password.clone(), 10);

		assertTrue(BcryptHasher.verify(password, hash));
	}

	@Test
	void testVerifyWrongPassword()
	{
		final char[] password = "testPassword123".toCharArray();
		final String hash = BcryptHasher.hash(password.clone(), 10);

		final char[] wrongPassword = "wrongPassword".toCharArray();
		assertFalse(BcryptHasher.verify(wrongPassword, hash));
	}

	@Test
	void testVerifyWithNullPassword()
	{
		assertThrows(IllegalArgumentException.class, () -> {
			BcryptHasher.verify(null, "$2a$10$...");
		});
	}

	@Test
	void testVerifyWithNullHash()
	{
		final char[] password = "testPassword123".toCharArray();
		assertThrows(IllegalArgumentException.class, () -> {
			BcryptHasher.verify(password, null);
		});
	}

	@Test
	void testGetLogRounds()
	{
		final char[] password = "testPassword123".toCharArray();

		final String hash10 = BcryptHasher.hash(password.clone(), 10);
		assertEquals(10, BcryptHasher.getLogRounds(hash10));

		final String hash14 = BcryptHasher.hash(password.clone(), 14);
		assertEquals(14, BcryptHasher.getLogRounds(hash14));
	}

	@Test
	void testHashProducesDifferentSalts()
	{
		final char[] password = "testPassword123".toCharArray();

		final String hash1 = BcryptHasher.hash(password.clone(), 10);
		final String hash2 = BcryptHasher.hash(password.clone(), 10);

		assertNotSame(hash1, hash2);
		assertTrue(BcryptHasher.verify(password.clone(), hash1));
		assertTrue(BcryptHasher.verify(password.clone(), hash2));
	}

	@Test
	void testPasswordArrayCleared()
	{
		final char[] password = "testPassword123".toCharArray();
		final char[] originalCopy = password.clone();

		BcryptHasher.hash(password, 10);

		assertFalse(java.util.Arrays.equals(originalCopy, password));
	}

	@Test
	void testHashWithSalt()
	{
		final char[] password = "testPassword123".toCharArray();
		final byte[] salt = new byte[16];
		new java.security.SecureRandom().nextBytes(salt);

		final String hash = BcryptHasher.hashWithSalt(password.clone(), salt, 10);

		assertNotNull(hash);
		assertTrue(hash.startsWith("$2y$10$"));
		assertTrue(BcryptHasher.verify(password, hash));
	}

	@Test
	void testHashWithSaltTooShort()
	{
		final char[] password = "testPassword123".toCharArray();
		final byte[] shortSalt = new byte[8];

		assertThrows(IllegalArgumentException.class, () -> {
			BcryptHasher.hashWithSalt(password, shortSalt, 10);
		});
	}

}
