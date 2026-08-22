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
package io.github.astrapi69.mystic.crypt.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for the {@code hash} subcommand.
 */
class HashCommandTest extends AbstractCliTest
{

	@ParameterizedTest
	@ValueSource(strings = { "argon2id", "pbkdf2" })
	void hashesWithEachAlgorithm(String algorithm)
	{
		assertEquals(0, run("hash", "--algorithm", algorithm, "--password", "secret"));
		assertTrue(out.strip().length() > 0, "an encoded hash must be printed");
	}

	@Test
	void defaultAlgorithmIsArgon2id()
	{
		assertEquals(0, run("hash", "--password", "secret"));
		assertTrue(out.contains("argon2"), "the default algorithm must be Argon2id");
	}

	@Test
	void readsPasswordFromStdin()
	{
		assertEquals(0,
			runWithStdin("piped-secret\n", "hash", "--algorithm", "pbkdf2", "--password-stdin"));
		assertTrue(out.strip().length() > 0);
	}

	@Test
	void differentPasswordsProduceDifferentHashes()
	{
		run("hash", "--algorithm", "pbkdf2", "--password", "a");
		String first = out.strip();
		run("hash", "--algorithm", "pbkdf2", "--password", "b");
		String second = out.strip();
		assertNotEquals(first, second);
	}

	@Test
	void missingPasswordFails()
	{
		assertNotEquals(0, run("hash", "--algorithm", "pbkdf2"),
			"without a password the command must fail");
	}
}
