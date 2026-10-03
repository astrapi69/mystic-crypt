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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The conversions that must not go through a {@link String}, and the overwriting they exist for
 * (#294)
 */
class SecretBuffersTest
{

	@ParameterizedTest(name = "\"{0}\" survives the trip through UTF-8 bytes and back")
	@ValueSource(strings = { "plain ascii", "Grüße aus München", "中文", "emoji: 🔐",
			"<xml attr=\"&amp;\"/>", " leading and trailing " })
	void charactersSurvive_theRoundTrip_throughUtf8(final String text)
	{
		char[] characters = text.toCharArray();

		char[] readBack = SecretBuffers.fromUtf8(SecretBuffers.toUtf8(characters));

		assertArrayEquals(characters, readBack);
	}

	@Test
	@DisplayName("the bytes are the same UTF-8 a String would have produced")
	void toUtf8_produces_whatTheCharsetProduces()
	{
		String text = "Grüße 🔐";

		assertArrayEquals(text.getBytes(StandardCharsets.UTF_8),
			SecretBuffers.toUtf8(text.toCharArray()),
			"the encoding must not change - a vault written through this is read by everything "
				+ "that reads UTF-8");
	}

	@Test
	@DisplayName("the empty array converts both ways")
	void theEmptyArray_isNot_aSpecialCase()
	{
		assertEquals(0, SecretBuffers.toUtf8(new char[0]).length);
		assertEquals(0, SecretBuffers.fromUtf8(new byte[0]).length);
	}

	@Test
	@DisplayName("converting reads the caller's array and leaves it alone")
	void theCallersArray_isNot_modified()
	{
		char[] characters = "the master password".toCharArray();
		char[] asHandedOver = characters.clone();
		byte[] bytes = SecretBuffers.toUtf8(characters);
		byte[] bytesAsHandedOver = bytes.clone();

		SecretBuffers.fromUtf8(bytes);

		assertArrayEquals(asHandedOver, characters);
		assertArrayEquals(bytesAsHandedOver, bytes);
	}

	@Test
	@DisplayName("wiping overwrites, and accepts nothing to wipe")
	void wipe_overwrites_andToleratesNull()
	{
		char[] characters = "secret".toCharArray();
		byte[] bytes = "secret".getBytes(StandardCharsets.UTF_8);

		SecretBuffers.wipe(characters);
		SecretBuffers.wipe(bytes);
		SecretBuffers.wipe((char[])null);
		SecretBuffers.wipe((byte[])null);

		assertArrayEquals(new char[characters.length], characters);
		assertArrayEquals(new byte[bytes.length], bytes);
		assertTrue(true, "and neither null throws - a close path must not fail on an empty vault");
	}

	@Test
	@DisplayName("a buffer that will not hand out its array is left alone rather than throwing")
	void aBufferWithoutAnAccessibleArray_isLeftAlone()
	{
		ByteBuffer direct = ByteBuffer.allocateDirect(8);
		CharBuffer readOnly = CharBuffer.wrap("secret".toCharArray()).asReadOnlyBuffer();

		assertFalse(direct.hasArray(), "precondition: a direct buffer has no accessible array");
		assertFalse(readOnly.hasArray(), "precondition: a read-only buffer refuses its array");

		assertDoesNotThrow(() -> SecretBuffers.wipeBackingArrayOf(direct),
			"array() throws on such a buffer, which is what the guard is for - the conversions "
				+ "here get heap buffers from the charset today, and nothing in that contract "
				+ "promises they always will");
		assertDoesNotThrow(() -> SecretBuffers.wipeBackingArrayOf(readOnly));
	}
}
