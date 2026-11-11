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
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Pins the defect of #294: hash and the keystore subcommands answer a missing secret with a Java
 * stack trace and exit code 1, where every other command that takes a secret prints one error: line
 * and exits 2 - and 1 is the code of a domain answer in this command line (verify-signature: 0
 * valid, 1 invalid, 2 error). The next commit turns these assertions.
 */
class CliErrorAnswerTest extends AbstractCliTest
{

	@Test
	@DisplayName("hash without a secret source answers a stack trace and exit 1, the defect")
	void hash_withoutASecretSource_printsAStackTraceAndExitsOne()
	{
		int exitCode = run("hash", "-a", "argon2id");

		assertEquals(1, exitCode);
		assertTrue(err.contains("\tat "), "the defect: a stack trace reaches the user");
	}

	@Test
	@DisplayName("keystore list without a password answers a stack trace and exit 1, the defect")
	void keystoreList_withoutAPassword_printsAStackTraceAndExitsOne()
	{
		String keystore = "src/test/resources/keystore.jks";

		int exitCode = run("keystore", "list", "--file", keystore);

		assertEquals(1, exitCode);
		assertTrue(err.contains("\tat "), "the defect: a stack trace reaches the user");
	}
}
