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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Test class for {@link Blake2sHasher}.
 */
class Blake2sHasherTest
{

	/**
	 * A known-answer vector (RFC 7693). The expected digests were generated with
	 * {@code printf '<input>' | openssl dgst -blake2s256 -r}, so a mismatch here means Bouncy
	 * Castle's BLAKE2s disagrees with OpenSSL - not a typo in this file. Without these, a mutant
	 * that swaps in any other hash would satisfy every length/determinism/sensitivity assertion in
	 * this class.
	 */
	record Vector(String description, String input, String expectedHex) {
	}

	static Stream<Vector> knownAnswerVectors()
	{
		return Stream.of(
			new Vector("empty input, 256 bit", "",
				"69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"),
			new Vector("abc, 256 bit", "abc",
				"508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"));
	}

	@ParameterizedTest
	@MethodSource("knownAnswerVectors")
	void testKnownAnswerVectors(Vector vector)
	{
		byte[] hash = Blake2sHasher.hash(vector.input().getBytes(StandardCharsets.UTF_8),
			Blake2sHasher.DEFAULT_DIGEST_LENGTH);
		assertEquals(vector.expectedHex(), HexFormat.of().formatHex(hash), vector.description());
	}

	@Test
	void testHashDefaultLength()
	{
		byte[] hash = Blake2sHasher.hash("hello".getBytes(StandardCharsets.UTF_8));
		assertEquals(Blake2sHasher.DEFAULT_DIGEST_LENGTH, hash.length);
	}

	@Test
	void testHashIsDeterministic()
	{
		byte[] data = "deterministic".getBytes(StandardCharsets.UTF_8);
		assertArrayEquals(Blake2sHasher.hash(data), Blake2sHasher.hash(data));
	}

	@Test
	void testDifferentDataProducesDifferentHash()
	{
		byte[] hash1 = Blake2sHasher.hash("first".getBytes(StandardCharsets.UTF_8));
		byte[] hash2 = Blake2sHasher.hash("second".getBytes(StandardCharsets.UTF_8));
		assertFalse(Arrays.equals(hash1, hash2));
	}

	@Test
	void testHashWithCustomLength()
	{
		byte[] hash = Blake2sHasher.hash("hello".getBytes(StandardCharsets.UTF_8), 16);
		assertEquals(16, hash.length);
	}

	@Test
	void testHashRejectsNullData()
	{
		assertThrows(IllegalArgumentException.class, () -> Blake2sHasher.hash((byte[])null));
	}

	@Test
	void testHashRejectsOutOfRangeDigestLength()
	{
		byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
		assertThrows(IllegalArgumentException.class, () -> Blake2sHasher.hash(data, 0));
		assertThrows(IllegalArgumentException.class, () -> Blake2sHasher.hash(data, 33));
	}

	@Test
	void testHashUtf8MatchesHashWithUtf8Charset()
	{
		String data = "hello world";
		assertArrayEquals(Blake2sHasher.hash(data, StandardCharsets.UTF_8),
			Blake2sHasher.hashUtf8(data));
	}

	@Test
	void testHashUtf8WithCustomLength()
	{
		byte[] hash = Blake2sHasher.hashUtf8("hello", 16);
		assertEquals(16, hash.length);
	}

	@Test
	void testHashStringRejectsNullCharset()
	{
		assertThrows(IllegalArgumentException.class, () -> Blake2sHasher.hash("hello", null));
	}

	@Test
	void testHashWithKeyDefaultLength()
	{
		byte[] key = "secret-key".getBytes(StandardCharsets.UTF_8);
		byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
		byte[] mac = Blake2sHasher.hashWithKey(data, key, Blake2sHasher.DEFAULT_DIGEST_LENGTH);
		assertEquals(Blake2sHasher.DEFAULT_DIGEST_LENGTH, mac.length);
	}

	@Test
	void testHashWithKeyShorterThanDefaultLength()
	{
		byte[] key = "secret-key".getBytes(StandardCharsets.UTF_8);
		byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
		byte[] mac = Blake2sHasher.hashWithKey(data, key, 16);
		assertEquals(16, mac.length);
	}

	@Test
	void testHashWithKeyIsDeterministicAndKeyDependent()
	{
		byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
		byte[] key1 = "key-one".getBytes(StandardCharsets.UTF_8);
		byte[] key2 = "key-two".getBytes(StandardCharsets.UTF_8);

		byte[] mac1a = Blake2sHasher.hashWithKey(data, key1, 16);
		byte[] mac1b = Blake2sHasher.hashWithKey(data, key1, 16);
		byte[] mac2 = Blake2sHasher.hashWithKey(data, key2, 16);

		assertArrayEquals(mac1a, mac1b);
		assertFalse(Arrays.equals(mac1a, mac2));
	}

	@Test
	void testHashWithNullKeyMatchesUnkeyedHash()
	{
		byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
		assertArrayEquals(Blake2sHasher.hash(data, 16), Blake2sHasher.hashWithKey(data, null, 16));
	}

	@Test
	void testHashWithKeyRejectsOversizedKey()
	{
		byte[] oversizedKey = new byte[33];
		byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
		assertThrows(IllegalArgumentException.class,
			() -> Blake2sHasher.hashWithKey(data, oversizedKey, 16));
	}

	@Test
	void testHashUtf8WithKey()
	{
		byte[] key = "secret-key".getBytes(StandardCharsets.UTF_8);
		byte[] mac = Blake2sHasher.hashUtf8WithKey("hello", key, 16);
		assertArrayEquals(mac,
			Blake2sHasher.hashWithKey("hello".getBytes(StandardCharsets.UTF_8), key, 16));
	}
}
