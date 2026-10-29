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

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

import io.github.astrapi69.mystic.crypt.gnupg.KeyRingState;
import io.github.astrapi69.mystic.crypt.gnupg.KeyState;

/**
 * The JSON form of {@code release-key status}. Written here rather than through a JSON library: the
 * structure is fixed and small, and the one library on hand that writes JSON would bring YAML, XML
 * and JSON schema support into every consumer of this library for it. The strings are escaped as
 * RFC 8259 requires, and the test reads the output back with a JSON parser.
 */
final class ReleaseKeyJson
{

	private ReleaseKeyJson()
	{
	}

	/**
	 * The status as one JSON object: the home and its certificates, each with its keys
	 *
	 * @param gnuPgHome
	 *            the home that was read
	 * @param certificates
	 *            the certificates to write
	 * @return the JSON text
	 */
	static String of(final Path gnuPgHome, final List<KeyRingState> certificates)
	{
		return "{\"home\":" + quoted(gnuPgHome.toString()) + ",\"certificates\":[" + certificates
			.stream().map(ReleaseKeyJson::certificateOf).collect(Collectors.joining(",")) + "]}";
	}

	private static String certificateOf(final KeyRingState certificate)
	{
		return "{\"fingerprint\":" + quoted(certificate.fingerprint()) + ",\"userId\":"
			+ quoted(certificate.userId()) + ",\"revocationCertificate\":"
			+ quoted(certificate.revocationCertificate().name()) + ",\"keys\":[" + certificate
				.keys().stream().map(ReleaseKeyJson::keyOf).collect(Collectors.joining(","))
			+ "]}";
	}

	private static String keyOf(final KeyState keyState)
	{
		return "{\"fingerprint\":" + quoted(keyState.fingerprint()) + ",\"primary\":"
			+ keyState.primary() + ",\"algorithm\":" + quoted(keyState.algorithm()) + ",\"usage\":"
			+ quoted(keyState.usage()) + ",\"created\":" + instantOf(keyState.created())
			+ ",\"expires\":" + instantOf(keyState.expires()) + ",\"secret\":"
			+ quoted(keyState.secret().name()) + "}";
	}

	private static String instantOf(final Instant instant)
	{
		return instant == null ? "null" : quoted(instant.toString());
	}

	/** A JSON string: quotes, backslashes and control characters escaped */
	static String quoted(final String text)
	{
		StringBuilder quoted = new StringBuilder("\"");
		for (char character : text.toCharArray())
		{
			switch (character)
			{
				case '"' -> quoted.append("\\\"");
				case '\\' -> quoted.append("\\\\");
				case '\n' -> quoted.append("\\n");
				case '\r' -> quoted.append("\\r");
				case '\t' -> quoted.append("\\t");
				default -> {
					if (character < 0x20)
					{
						quoted.append(String.format("\\u%04x", (int)character));
					}
					else
					{
						quoted.append(character);
					}
				}
			}
		}
		return quoted.append('"').toString();
	}
}
