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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Where {@link SecretInput} takes a secret from, and in which order: standard input first, then the
 * argument that is going away (with a warning), then a prompt in a terminal - which a test JVM does
 * not have (#214)
 */
class SecretInputTest
{

	private InputStream originalIn;

	private PrintStream originalErr;

	private final ByteArrayOutputStream err = new ByteArrayOutputStream();

	@BeforeEach
	void captureStandardError()
	{
		originalIn = System.in;
		originalErr = System.err;
		System.setErr(new PrintStream(err, true, StandardCharsets.UTF_8));
	}

	@AfterEach
	void restoreTheStreams()
	{
		System.setIn(originalIn);
		System.setErr(originalErr);
	}

	private String standardError()
	{
		return err.toString(StandardCharsets.UTF_8);
	}

	@Test
	@DisplayName("standard input wins over the argument and warns about nothing")
	void standardInput_winsOverTheArgument()
	{
		System.setIn(new ByteArrayInputStream("from-stdin\n".getBytes(StandardCharsets.UTF_8)));

		assertEquals("from-stdin", SecretInput.PASSWORD.resolveText("from-argument", true));
		assertEquals("", standardError());
	}

	@Test
	@DisplayName("the argument still works and says on standard error that it goes away in 14.0")
	void theArgument_works_andWarns()
	{
		assertArrayEquals("secret".toCharArray(), SecretInput.PASSPHRASE.resolve("secret", false));

		String warning = standardError();
		assertTrue(warning.contains("--passphrase puts the passphrase into the process arguments")
			&& warning.contains("--passphrase-stdin") && warning.contains("14.0"), warning);
	}

	@Test
	@DisplayName("nothing given and no terminal: refused, naming the standard input flag")
	void nothing_withoutATerminal_isRefused()
	{
		IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
			() -> SecretInput.MAC_KEY.resolve(null, false));

		assertEquals(
			"a MAC key is required: pass --key-stdin, or run in a terminal to be asked for it",
			refused.getMessage());
	}

	@Test
	@DisplayName("an empty argument means: ask, as keystore -p without a value always did")
	void anEmptyArgument_asks()
	{
		IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
			() -> SecretInput.KEY_STORE_PASSWORD.resolve("", false));

		assertTrue(refused.getMessage().contains("terminal"), refused.getMessage());
		assertEquals("", standardError());
	}

	@Test
	@DisplayName("an empty standard input is refused rather than taken as an empty secret")
	void emptyStandardInput_isRefused()
	{
		System.setIn(new ByteArrayInputStream(new byte[0]));

		IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
			() -> SecretInput.SHARED_SECRET.resolve(null, true));

		assertEquals("no secret was provided on standard input", refused.getMessage());
	}

	@Test
	@DisplayName("standard input that cannot be read is refused with the reason")
	void unreadableStandardInput_isRefused()
	{
		System.setIn(CliSupportTest.failingStdin());

		IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
			() -> SecretInput.PASSWORD.resolve(null, true));

		assertTrue(refused.getMessage().contains("boom"), refused.getMessage());
	}
}
