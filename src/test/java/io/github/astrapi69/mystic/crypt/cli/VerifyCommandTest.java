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
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for the {@code verify} subcommand: exit code 0 = matches, 1 = does not match.
 */
class VerifyCommandTest extends AbstractCliTest
{

	private String hash(String algorithm, String password)
	{
		run("hash", "--algorithm", algorithm, "--password", password);
		return out.strip();
	}

	@ParameterizedTest
	@ValueSource(strings = { "argon2id", "pbkdf2" })
	void correctPasswordVerifies(String algorithm)
	{
		String hash = hash(algorithm, "the-secret");
		assertEquals(0,
			run("verify", "--algorithm", algorithm, "--hash", hash, "--password", "the-secret"));
		assertTrue(out.contains("matches"));
	}

	@ParameterizedTest
	@ValueSource(strings = { "argon2id", "pbkdf2" })
	void wrongPasswordDoesNotVerify(String algorithm)
	{
		String hash = hash(algorithm, "the-secret");
		assertEquals(1,
			run("verify", "--algorithm", algorithm, "--hash", hash, "--password", "wrong"));
		assertTrue(out.contains("does not match"));
	}

	@org.junit.jupiter.api.Test
	void readsPasswordFromStdin()
	{
		String hash = hash("pbkdf2", "piped");
		assertEquals(0, runWithStdin("piped\n", "verify", "--algorithm", "pbkdf2", "--hash", hash,
			"--password-stdin"));
	}
}
