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

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for the {@code kem} subcommand.
 */
class KemCommandTest extends AbstractCliTest
{

	@ParameterizedTest
	@ValueSource(strings = { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "hybrid" })
	void bothPartiesDeriveMatchingSecrets(String algorithm)
	{
		assertEquals(0, run("kem", "--algorithm", algorithm));
		assertTrue(out.contains("shared secrets match"),
			algorithm + " sender and recipient must derive the same secret");
		assertTrue(out.contains("ciphertext:"), "must print the ciphertext");
		assertTrue(out.contains("sender-secret:") && out.contains("recipient-secret:"));
	}

	@org.junit.jupiter.api.Test
	void hybridIsCaseInsensitive()
	{
		assertEquals(0, run("kem", "--algorithm", "HYBRID"));
		assertTrue(out.contains("shared secrets match"));
	}

	@org.junit.jupiter.api.Test
	void unknownAlgorithmFails()
	{
		assertNotEquals(0, run("kem", "--algorithm", "ML-KEM-999"));
	}

	@org.junit.jupiter.api.Test
	void reportReturnsOneAndReportsNoMatchForDifferingSecrets()
	{
		java.io.PrintStream originalOut = System.out;
		java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
		System
			.setOut(new java.io.PrintStream(buffer, true, java.nio.charset.StandardCharsets.UTF_8));
		int exitCode;
		try
		{
			exitCode = KemCommand.report("test", new byte[] { 9 }, new byte[] { 1 },
				new byte[] { 2 });
		}
		finally
		{
			System.setOut(originalOut);
		}
		assertEquals(1, exitCode, "differing secrets must return exit code 1");
		assertTrue(buffer.toString(java.nio.charset.StandardCharsets.UTF_8)
			.contains("shared secrets do not match"));
	}
}
