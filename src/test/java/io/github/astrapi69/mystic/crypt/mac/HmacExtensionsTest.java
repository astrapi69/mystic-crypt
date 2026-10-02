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
package io.github.astrapi69.mystic.crypt.mac;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

import io.github.astrapi69.crypt.api.algorithm.MacAlgorithm;
import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * HMAC against the known answers of RFC 4231, section 4 (#163). The values were recomputed with
 * Python's hmac module before they went in here, so the test does not rest on a copied table alone.
 */
class HmacExtensionsTest
{

	private static final HexFormat HEX = HexFormat.of();

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	@ParameterizedTest(name = "RFC 4231 {0}")
	@CsvSource({
			"test case 1 HMAC-SHA-512, HmacSHA512, 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b, Hi There, 87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
			"test case 1 HMAC-SHA-256, HmacSHA256, 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b, Hi There, b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
			"test case 2 HMAC-SHA-512, HmacSHA512, 4a656665, what do ya want for nothing?, 164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737" })
	void hmac_givesTheKnownAnswersOfRfc4231(final String name, final MacAlgorithm algorithm,
		final String key, final String message, final String expected)
	{
		assertArrayEquals(HEX.parseHex(expected), HmacExtensions.hmac(algorithm, HEX.parseHex(key),
			message.getBytes(StandardCharsets.US_ASCII)));
	}

	@Test
	void hmac_hashesAKeyLongerThanTheBlockFirst_rfc4231TestCase6()
	{
		byte[] key = new byte[131];
		Arrays.fill(key, (byte)0xaa);

		assertArrayEquals(HEX.parseHex(
			"80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598"),
			HmacExtensions.hmac(MacAlgorithm.HmacSHA512, key,
				"Test Using Larger Than Block-Size Key - Hash Key First"
					.getBytes(StandardCharsets.US_ASCII)));
	}

	@Test
	void hmac_refusesAnEmptyKey_insteadOfMacingWithNone()
	{
		IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
			() -> HmacExtensions.hmac(MacAlgorithm.HmacSHA512, new byte[0], new byte[] { 1 }));

		// SecretKeySpec refuses an empty key as well, with "Empty key"; this message says which
		// algorithm was asked for, so a report about it needs no follow-up question
		org.junit.jupiter.api.Assertions.assertTrue(
			refused.getMessage().contains("0 bytes") && refused.getMessage().contains("HmacSHA512"),
			refused.getMessage());
	}

	/**
	 * MacAlgorithm also names values no raw key can drive: the PBE variants want a password based
	 * key, and UNKNOWN names no algorithm at all. That is the caller's mistake, not a defect of the
	 * runtime, so it is an IllegalArgumentException that names the value
	 */
	@ParameterizedTest(name = "{0} is refused as an argument")
	@EnumSource(value = MacAlgorithm.class, names = { "UNKNOWN", "PBEWithHmacSHA1",
			"PBEWithHmacSHA256", "PBEWithHmacSHA512" })
	void hmac_refusesAValueThatIsNoHmacOverARawKey(final MacAlgorithm algorithm)
	{
		IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
			() -> HmacExtensions.hmac(algorithm, new byte[] { 1, 2, 3 }, new byte[] { 1 }));

		org.junit.jupiter.api.Assertions.assertTrue(refused.getMessage().contains(algorithm.name()),
			refused.getMessage());
	}

	/** The other side of the refusal above: every raw-key HMAC the enum names is computed */
	@ParameterizedTest(name = "{0} is computed")
	@EnumSource(value = MacAlgorithm.class, mode = EnumSource.Mode.MATCH_ANY, names = { "Hmac.*",
			"H_MAC_.*" })
	void hmac_computesEveryRawKeyHmacTheEnumNames(final MacAlgorithm algorithm)
	{
		byte[] code = HmacExtensions.hmac(algorithm, new byte[] { 1, 2, 3 }, new byte[] { 1 });

		org.junit.jupiter.api.Assertions.assertTrue(code.length >= 16,
			algorithm + " gave " + code.length + " bytes");
	}
}
