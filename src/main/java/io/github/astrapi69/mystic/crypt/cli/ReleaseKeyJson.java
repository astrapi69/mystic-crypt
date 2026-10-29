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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.github.astrapi69.mystic.crypt.gnupg.KeyRingState;
import io.github.astrapi69.mystic.crypt.gnupg.KeyState;

/**
 * The JSON form of {@code release-key status}, written with Jackson, which this library already has
 * at runtime through randomizer. The tree is built by hand rather than by mapping the records, so
 * the field names and the form of the dates are fixed here and do not follow a refactoring of the
 * records.
 */
final class ReleaseKeyJson
{

	private static final ObjectMapper MAPPER = new ObjectMapper();

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
		ObjectNode status = MAPPER.createObjectNode();
		status.put("home", gnuPgHome.toString());
		ArrayNode certificateNodes = status.putArray("certificates");
		for (KeyRingState certificate : certificates)
		{
			ObjectNode certificateNode = certificateNodes.addObject();
			certificateNode.put("fingerprint", certificate.fingerprint());
			certificateNode.put("userId", certificate.userId());
			certificateNode.put("revocationCertificate",
				certificate.revocationCertificate().name());
			ArrayNode keyNodes = certificateNode.putArray("keys");
			certificate.keys().forEach(keyState -> describe(keyNodes.addObject(), keyState));
		}
		return status.toString();
	}

	private static void describe(final ObjectNode keyNode, final KeyState keyState)
	{
		keyNode.put("fingerprint", keyState.fingerprint());
		keyNode.put("primary", keyState.primary());
		keyNode.put("algorithm", keyState.algorithm());
		keyNode.put("usage", keyState.usage());
		keyNode.put("created", keyState.created().toString());
		keyNode.put("expires", instantOf(keyState.expires()));
		keyNode.put("secret", keyState.secret().name());
	}

	private static String instantOf(final Instant instant)
	{
		return instant == null ? null : instant.toString();
	}
}
