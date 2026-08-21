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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * Test class for {@link Blake2bHasher}.
 */
class Blake2bHasherTest
{

	@Test
	void testHashDefaultLength()
	{
		byte[] hash = Blake2bHasher.hash("hello".getBytes(StandardCharsets.UTF_8));
		assertEquals(Blake2bHasher.DEFAULT_DIGEST_LENGTH, hash.length);
	}

	@Test
	void testHashIsDeterministic()
	{
		byte[] data = "deterministic".getBytes(StandardCharsets.UTF_8);
		assertArrayEquals(Blake2bHasher.hash(data), Blake2bHasher.hash(data));
	}

	@Test
	void testDifferentDataProducesDifferentHash()
	{
		byte[] hash1 = Blake2bHasher.hash("first".getBytes(StandardCharsets.UTF_8));
		byte[] hash2 = Blake2bHasher.hash("second".getBytes(StandardCharsets.UTF_8));
		assertFalse(Arrays.equals(hash1, hash2));
	}

	@Test
	void testHashWithCustomLength()
	{
		byte[] hash = Blake2bHasher.hash("hello".getBytes(StandardCharsets.UTF_8), 32);
		assertEquals(32, hash.length);
	}

	@Test
	void testHashRejectsNullData()
	{
		assertThrows(IllegalArgumentException.class, () -> Blake2bHasher.hash((byte[])null));
	}

	@Test
	void testHashRejectsOutOfRangeDigestLength()
	{
		byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
		assertThrows(IllegalArgumentException.class, () -> Blake2bHasher.hash(data, 0));
		assertThrows(IllegalArgumentException.class, () -> Blake2bHasher.hash(data, 65));
	}

	@Test
	void testHashUtf8MatchesHashWithUtf8Charset()
	{
		String data = "hello world";
		assertArrayEquals(Blake2bHasher.hash(data, StandardCharsets.UTF_8),
			Blake2bHasher.hashUtf8(data));
	}

	@Test
	void testHashUtf8WithCustomLength()
	{
		byte[] hash = Blake2bHasher.hashUtf8("hello", 16);
		assertEquals(16, hash.length);
	}

	@Test
	void testHashStringRejectsNullCharset()
	{
		assertThrows(IllegalArgumentException.class, () -> Blake2bHasher.hash("hello", null));
	}

	@Test
	void testHashWithKeyDefaultLength()
	{
		byte[] key = "secret-key".getBytes(StandardCharsets.UTF_8);
		byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
		byte[] mac = Blake2bHasher.hashWithKey(data, key, Blake2bHasher.DEFAULT_DIGEST_LENGTH);
		assertEquals(Blake2bHasher.DEFAULT_DIGEST_LENGTH, mac.length);
	}

	@Test
	void testHashWithKeyShorterThanDefaultLength()
	{
		byte[] key = "secret-key".getBytes(StandardCharsets.UTF_8);
		byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
		byte[] mac = Blake2bHasher.hashWithKey(data, key, 32);
		assertEquals(32, mac.length);
	}

	@Test
	void testHashWithKeyIsDeterministicAndKeyDependent()
	{
		byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
		byte[] key1 = "key-one".getBytes(StandardCharsets.UTF_8);
		byte[] key2 = "key-two".getBytes(StandardCharsets.UTF_8);

		byte[] mac1a = Blake2bHasher.hashWithKey(data, key1, 32);
		byte[] mac1b = Blake2bHasher.hashWithKey(data, key1, 32);
		byte[] mac2 = Blake2bHasher.hashWithKey(data, key2, 32);

		assertArrayEquals(mac1a, mac1b);
		assertFalse(Arrays.equals(mac1a, mac2));
	}

	@Test
	void testHashWithNullKeyMatchesUnkeyedHash()
	{
		byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
		assertArrayEquals(Blake2bHasher.hash(data, 32), Blake2bHasher.hashWithKey(data, null, 32));
	}

	@Test
	void testHashWithKeyRejectsOversizedKey()
	{
		byte[] oversizedKey = new byte[65];
		byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
		assertThrows(IllegalArgumentException.class,
			() -> Blake2bHasher.hashWithKey(data, oversizedKey, 32));
	}

	@Test
	void testHashUtf8WithKey()
	{
		byte[] key = "secret-key".getBytes(StandardCharsets.UTF_8);
		byte[] mac = Blake2bHasher.hashUtf8WithKey("hello", key, 32);
		assertArrayEquals(mac,
			Blake2bHasher.hashWithKey("hello".getBytes(StandardCharsets.UTF_8), key, 32));
	}
}
