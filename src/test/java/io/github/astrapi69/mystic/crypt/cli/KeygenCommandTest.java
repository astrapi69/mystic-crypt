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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for the {@code keygen} subcommand.
 */
class KeygenCommandTest extends AbstractCliTest
{

	@Test
	void generatesRsaKeyPairWithKeySize()
	{
		assertEquals(0, run("keygen", "--algorithm", "RSA", "--size", "2048"));
		assertTrue(out.contains("PRIVATE KEY"));
		assertTrue(out.contains("PUBLIC KEY"));
	}

	@ParameterizedTest
	@ValueSource(strings = { "X25519", "X448", "ML-KEM-768", "ML-DSA-65" })
	void generatesModernAlgorithmKeyPair(String algorithm)
	{
		assertEquals(0, run("keygen", "--algorithm", algorithm));
		assertTrue(out.contains("PRIVATE KEY"), "must print a private key PEM for " + algorithm);
		assertTrue(out.contains("PUBLIC KEY"), "must print a public key PEM for " + algorithm);
	}

	@Test
	void writesKeysToFiles(@TempDir File tempDir) throws Exception
	{
		File privateFile = new File(tempDir, "priv.pem");
		File publicFile = new File(tempDir, "pub.pem");
		assertEquals(0, run("keygen", "--algorithm", "X25519", "--out-private",
			privateFile.getAbsolutePath(), "--out-public", publicFile.getAbsolutePath()));

		assertTrue(Files.readString(privateFile.toPath()).contains("PRIVATE KEY"));
		assertTrue(Files.readString(publicFile.toPath()).contains("PUBLIC KEY"));
		assertTrue(out.isBlank(), "with output files nothing goes to stdout");
	}

	@Test
	void unknownAlgorithmFails()
	{
		assertNotEquals(0, run("keygen", "--algorithm", "NOPE"));
	}
}
