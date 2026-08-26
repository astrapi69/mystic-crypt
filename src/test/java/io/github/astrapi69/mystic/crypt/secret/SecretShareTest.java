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
package io.github.astrapi69.mystic.crypt.secret;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for {@link SecretShare}, the text format one share is written in.
 */
class SecretShareTest
{

	private static final byte[] VALUE = { 0x01, 0x02, 0x03, 0x04, (byte)0xff };

	@Test
	void aShareSurvivesTheRoundTripThroughItsTextForm()
	{
		SecretShare share = new SecretShare("00112233445566aa", 3, 5, 2, VALUE);

		SecretShare parsed = SecretShare.decode(share.encode());

		assertEquals("00112233445566aa", parsed.getSplitId());
		assertEquals(3, parsed.getThreshold());
		assertEquals(5, parsed.getTotal(), "the share must carry how many shares the split made");
		assertEquals(2, parsed.getIndex());
		assertArrayEquals(VALUE, parsed.getValue());
	}

	@Test
	void theEncodedLineStartsWithTheFormatPrefix()
	{
		assertTrue(
			new SecretShare("abcd", 2, 3, 1, VALUE).encode().startsWith(SecretShare.PREFIX + ":"),
			"a share line must be recognisable by its prefix");
	}

	/**
	 * Every one of these is a line that could arrive from a person copying a share by hand, and
	 * each must be named rather than silently accepted.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "", "just some text", "mcs1:only:four:fields",
			"mcs1:a:2:3:1:AAAA:dead:beef", "nope:a:2:3:1:AAAA:deadbeef" })
	@NullSource
	void aLineThatIsNotAShareIsRejectedWithAnExampleOfOneThatIs(String line)
	{
		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> SecretShare.decode(line));

		assertTrue(rejected.getMessage().contains(SecretShare.PREFIX),
			"the message must show what a share line looks like, but was: '" + rejected.getMessage()
				+ "'");
	}

	@ParameterizedTest
	@CsvSource({ "mcs1:a:two:3:1:AAAA:deadbeef, threshold", "mcs1:a:2:all:1:AAAA:deadbeef, total",
			"mcs1:a:2:3:first:AAAA:deadbeef, index" })
	void aNumericFieldThatIsNotANumberIsNamedByItsRole(String line, String expectedFieldName)
	{
		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> SecretShare.decode(line));

		assertTrue(rejected.getMessage().contains(expectedFieldName),
			"the message must name the field, but was: '" + rejected.getMessage() + "'");
	}

	@Test
	void aValueThatIsNotBase64IsNamedAsSuch()
	{
		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> SecretShare.decode("mcs1:a:2:3:1:not base64 at all:deadbeef"));

		assertTrue(rejected.getMessage().contains("base64url"),
			"the message must say what was expected, but was: '" + rejected.getMessage() + "'");
	}

	@Test
	void aChecksumThatDoesNotMatchNamesTheShareAndTheSplit()
	{
		String tamperedChecksum = new SecretShare("beefsplit", 2, 3, 7, VALUE).encode()
			.replaceAll(":[0-9a-f]{8}$", ":00000000");

		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> SecretShare.decode(tamperedChecksum));

		assertTrue(
			rejected.getMessage().contains("7") && rejected.getMessage().contains("beefsplit"),
			"the message must identify which share of which split, but was: '"
				+ rejected.getMessage() + "'");
	}

	@Test
	void anUnavailableDigestAlgorithmIsReportedRatherThanSwallowed()
	{
		assertThrows(IllegalStateException.class,
			() -> SecretShare.checksumOf("mcs1:a:2:3:1:AAAA", "NoSuchDigest-512"));
	}

	@Test
	void combineRefusesNothingToCombine()
	{
		assertThrows(IllegalArgumentException.class, () -> SecretSharing.combine(null));
		assertThrows(IllegalArgumentException.class, () -> SecretSharing.combine(List.of()));
	}

	@Test
	void aSingleShareOfAThreeShareSplitIsReportedInTheSingular()
	{
		List<SecretShare> shares = SecretSharing.split(
			"a secret with enough bytes".getBytes(java.nio.charset.StandardCharsets.UTF_8), 2, 3);

		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> SecretSharing.combine(List.of(shares.get(0))));

		assertTrue(rejected.getMessage().contains("1 was given"),
			"one share is 'was given', not 'were given', but the message was: '"
				+ rejected.getMessage() + "'");
	}
}
