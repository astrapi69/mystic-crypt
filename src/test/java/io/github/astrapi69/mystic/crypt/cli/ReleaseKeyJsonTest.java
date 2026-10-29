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
package io.github.astrapi69.mystic.crypt.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.json.JsonStringToObjectExtensions;
import io.github.astrapi69.mystic.crypt.gnupg.KeyRingState;
import io.github.astrapi69.mystic.crypt.gnupg.KeyState;
import io.github.astrapi69.mystic.crypt.gnupg.RevocationCertificate;
import io.github.astrapi69.mystic.crypt.gnupg.SecretPart;

/**
 * A user ID and a home path can hold anything a person typed, so every string the JSON carries
 * comes back unchanged through a JSON parser: quotes, backslashes, control characters and umlauts
 */
class ReleaseKeyJsonTest
{

	static Stream<Arguments> textsAPersonCanType()
	{
		return Stream.of(Arguments.of("plain", "Release Test <release@example.org>"),
			Arguments.of("a quote", "Jane \"JD\" Doe"), Arguments.of("a backslash", "C:\\keys"),
			Arguments.of("umlauts", "Jürgen Müßig <jm@example.org>"),
			Arguments.of("a line break and a tab", "one\nline\tmore\r"),
			Arguments.of("a control character", "bell\u0007here"), Arguments.of("empty", ""));
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("textsAPersonCanType")
	@SuppressWarnings("unchecked")
	void of_carriesEveryTextUnchanged(final String what, final String text) throws Exception
	{
		KeyState key = new KeyState("5B2FA6B11E298BC09287F423D8C403518C49CA75", true, "rsa2048",
			"SC", Instant.parse("2016-05-01T12:56:24Z"), null, SecretPart.OFFLINE);
		KeyRingState certificate = new KeyRingState(key.fingerprint(), text, List.of(key),
			RevocationCertificate.ABSENT);

		Map<String, Object> status = JsonStringToObjectExtensions
			.toObject(ReleaseKeyJson.of(Path.of("/home", text), List.of(certificate)), Map.class);

		assertEquals(Path.of("/home", text).toString(), status.get("home"));
		Map<String, Object> read = ((List<Map<String, Object>>)status.get("certificates")).get(0);
		assertEquals(text, read.get("userId"));
	}
}
