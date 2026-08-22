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
import java.util.stream.Stream;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.MessageDigestAlgorithm;

/**
 * Test class for {@link Sha3Hasher}.
 */
class Sha3HasherTest
{

	/**
	 * A known-answer vector. The expected digests were generated with
	 * {@code printf '<input>' | openssl dgst -sha3-<bits> -r} rather than copied from memory, so a
	 * mismatch here means the JDK's SHA-3 disagrees with OpenSSL's - not a typo in this file.
	 */
	record Vector(MessageDigestAlgorithm algorithm, String input, String expectedHex) {
	}

	static Stream<Vector> knownAnswerVectors()
	{
		return Stream.of(
			new Vector(MessageDigestAlgorithm.SHA3_224, "",
				"6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"),
			new Vector(MessageDigestAlgorithm.SHA3_224, "abc",
				"e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"),
			new Vector(MessageDigestAlgorithm.SHA3_256, "",
				"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
			new Vector(MessageDigestAlgorithm.SHA3_256, "abc",
				"3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
			new Vector(MessageDigestAlgorithm.SHA3_384, "",
				"0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"),
			new Vector(MessageDigestAlgorithm.SHA3_384, "abc",
				"ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"),
			new Vector(MessageDigestAlgorithm.SHA3_512, "",
				"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"),
			new Vector(MessageDigestAlgorithm.SHA3_512, "abc",
				"b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"));
	}

	@ParameterizedTest
	@MethodSource("knownAnswerVectors")
	void testKnownAnswerVectors(Vector vector)
	{
		byte[] digest = Sha3Hasher.hash(vector.input().getBytes(StandardCharsets.UTF_8),
			vector.algorithm());
		assertEquals(vector.expectedHex(), Hex.encodeHexString(digest));
	}

	record DigestLength(MessageDigestAlgorithm algorithm, int expectedBytes) {
	}

	static Stream<DigestLength> digestLengths()
	{
		return Stream.of(new DigestLength(MessageDigestAlgorithm.SHA3_224, 28),
			new DigestLength(MessageDigestAlgorithm.SHA3_256, 32),
			new DigestLength(MessageDigestAlgorithm.SHA3_384, 48),
			new DigestLength(MessageDigestAlgorithm.SHA3_512, 64));
	}

	@ParameterizedTest
	@MethodSource("digestLengths")
	void testDigestLengthMatchesVariant(DigestLength testCase)
	{
		byte[] digest = Sha3Hasher.hash("hello".getBytes(StandardCharsets.UTF_8),
			testCase.algorithm());
		assertEquals(testCase.expectedBytes(), digest.length);
	}

	@Test
	void testDefaultAlgorithmIsSha3_256()
	{
		byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
		assertEquals(MessageDigestAlgorithm.SHA3_256, Sha3Hasher.DEFAULT_ALGORITHM);
		assertArrayEquals(Sha3Hasher.hash(data, MessageDigestAlgorithm.SHA3_256),
			Sha3Hasher.hash(data));
		assertEquals(32, Sha3Hasher.hash(data).length);
	}

	@ParameterizedTest
	@EnumSource(value = MessageDigestAlgorithm.class, names = "SHA3_.*", mode = EnumSource.Mode.MATCH_ALL)
	void testIsDeterministic(MessageDigestAlgorithm algorithm)
	{
		byte[] data = "deterministic".getBytes(StandardCharsets.UTF_8);
		assertArrayEquals(Sha3Hasher.hash(data, algorithm), Sha3Hasher.hash(data, algorithm));
	}

	@ParameterizedTest
	@EnumSource(value = MessageDigestAlgorithm.class, names = "SHA3_.*", mode = EnumSource.Mode.MATCH_ALL)
	void testDifferentInputProducesDifferentDigest(MessageDigestAlgorithm algorithm)
	{
		byte[] first = Sha3Hasher.hash("first".getBytes(StandardCharsets.UTF_8), algorithm);
		byte[] second = Sha3Hasher.hash("second".getBytes(StandardCharsets.UTF_8), algorithm);
		assertFalse(Arrays.equals(first, second));
	}

	@Test
	void testVariantsProduceDifferentDigestsForSameInput()
	{
		byte[] data = "same input".getBytes(StandardCharsets.UTF_8);
		byte[] sha256 = Sha3Hasher.hash(data, MessageDigestAlgorithm.SHA3_256);
		byte[] sha512 = Sha3Hasher.hash(data, MessageDigestAlgorithm.SHA3_512);
		// not just a different length - the 256-bit digest is not a prefix of the 512-bit one
		assertFalse(Arrays.equals(sha256, Arrays.copyOf(sha512, sha256.length)));
	}

	@Test
	void testStringOverloadsMatchByteOverload()
	{
		String data = "hello world";
		byte[] viaBytes = Sha3Hasher.hash(data.getBytes(StandardCharsets.UTF_8),
			MessageDigestAlgorithm.SHA3_384);
		assertArrayEquals(viaBytes,
			Sha3Hasher.hash(data, StandardCharsets.UTF_8, MessageDigestAlgorithm.SHA3_384));
		assertArrayEquals(viaBytes, Sha3Hasher.hashUtf8(data, MessageDigestAlgorithm.SHA3_384));
		assertArrayEquals(Sha3Hasher.hash(data.getBytes(StandardCharsets.UTF_8)),
			Sha3Hasher.hash(data, StandardCharsets.UTF_8));
		assertArrayEquals(Sha3Hasher.hash(data.getBytes(StandardCharsets.UTF_8)),
			Sha3Hasher.hashUtf8(data));
	}

	@Test
	void testCharsetAffectsDigest()
	{
		String data = "grüße";
		byte[] utf8 = Sha3Hasher.hash(data, StandardCharsets.UTF_8);
		byte[] latin1 = Sha3Hasher.hash(data, StandardCharsets.ISO_8859_1);
		assertFalse(Arrays.equals(utf8, latin1));
	}

	@Test
	void testRejectsNullData()
	{
		assertThrows(IllegalArgumentException.class, () -> Sha3Hasher.hash((byte[])null));
		assertThrows(IllegalArgumentException.class,
			() -> Sha3Hasher.hash((byte[])null, MessageDigestAlgorithm.SHA3_256));
		assertThrows(IllegalArgumentException.class,
			() -> Sha3Hasher.hash((String)null, StandardCharsets.UTF_8));
		assertThrows(IllegalArgumentException.class, () -> Sha3Hasher.hashUtf8(null));
	}

	@Test
	void testRejectsNullCharset()
	{
		assertThrows(IllegalArgumentException.class, () -> Sha3Hasher.hash("hello", null));
	}

	@Test
	void testRejectsNullAlgorithm()
	{
		byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
		assertThrows(IllegalArgumentException.class, () -> Sha3Hasher.hash(data, null));
	}

	/**
	 * Every {@link MessageDigestAlgorithm} constant that is not a SHA-3 variant must be rejected,
	 * so that this class can never silently compute MD5 or SHA-2 under a SHA-3 name.
	 */
	@ParameterizedTest
	@EnumSource(value = MessageDigestAlgorithm.class, names = "SHA3_.*", mode = EnumSource.Mode.MATCH_NONE)
	void testRejectsNonSha3Algorithm(MessageDigestAlgorithm algorithm)
	{
		byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
			() -> Sha3Hasher.hash(data, algorithm));
		assertEquals("Not a SHA-3 algorithm: " + algorithm, exception.getMessage());
	}

}
