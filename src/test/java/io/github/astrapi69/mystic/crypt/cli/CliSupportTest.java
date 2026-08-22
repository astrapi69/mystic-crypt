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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;

/**
 * Unit tests for the shared {@link CliSupport} helpers, covering every branch including the error
 * paths.
 */
class CliSupportTest
{

	@Test
	void resolvePasswordFromArgument()
	{
		assertEquals("secret", CliSupport.resolvePassword("secret", false));
	}

	@Test
	void resolvePasswordFromStdin()
	{
		InputStream originalIn = System.in;
		System.setIn(new ByteArrayInputStream("from-stdin\n".getBytes(StandardCharsets.UTF_8)));
		try
		{
			assertEquals("from-stdin", CliSupport.resolvePassword(null, true));
		}
		finally
		{
			System.setIn(originalIn);
		}
	}

	@Test
	void resolvePasswordMissingThrows()
	{
		assertThrows(IllegalArgumentException.class, () -> CliSupport.resolvePassword(null, false));
	}

	@Test
	void resolvePasswordEmptyStdinThrows()
	{
		InputStream originalIn = System.in;
		System.setIn(new ByteArrayInputStream(new byte[0]));
		try
		{
			assertThrows(IllegalArgumentException.class,
				() -> CliSupport.resolvePassword(null, true));
		}
		finally
		{
			System.setIn(originalIn);
		}
	}

	@Test
	void resolveTextFromArgumentAndStdin()
	{
		assertEquals("hello", CliSupport.resolveText("hello", false));

		InputStream originalIn = System.in;
		System.setIn(new ByteArrayInputStream("piped".getBytes(StandardCharsets.UTF_8)));
		try
		{
			assertEquals("piped", CliSupport.resolveText(null, true));
		}
		finally
		{
			System.setIn(originalIn);
		}
	}

	@Test
	void resolveTextMissingThrows()
	{
		assertThrows(IllegalArgumentException.class, () -> CliSupport.resolveText(null, false));
	}

	/** An input stream that always fails, to exercise the stdin read-error branches. */
	private static InputStream failingStdin()
	{
		return new InputStream()
		{
			@Override
			public int read() throws java.io.IOException
			{
				throw new java.io.IOException("boom");
			}
		};
	}

	@Test
	void resolvePasswordStdinReadErrorThrows()
	{
		InputStream originalIn = System.in;
		System.setIn(failingStdin());
		try
		{
			assertThrows(IllegalArgumentException.class,
				() -> CliSupport.resolvePassword(null, true));
		}
		finally
		{
			System.setIn(originalIn);
		}
	}

	@Test
	void resolveTextStdinReadErrorThrows()
	{
		InputStream originalIn = System.in;
		System.setIn(failingStdin());
		try
		{
			assertThrows(IllegalArgumentException.class, () -> CliSupport.resolveText(null, true));
		}
		finally
		{
			System.setIn(originalIn);
		}
	}

	@ParameterizedTest
	@CsvSource({ "RSA,RSA", "rsa,RSA", "ML-KEM-768,ML_KEM_768", "ml_dsa_65,ML_DSA_65",
			"X25519,X25519" })
	void parseKeyPairAlgorithmAcceptsDashesAndCase(String input, KeyPairGeneratorAlgorithm expected)
	{
		assertEquals(expected, CliSupport.parseKeyPairAlgorithm(input));
	}

	@Test
	void parseKeyPairAlgorithmRejectsUnknown()
	{
		assertThrows(IllegalArgumentException.class,
			() -> CliSupport.parseKeyPairAlgorithm("no-such-algo"));
	}

	@ParameterizedTest
	@ValueSource(strings = { "RSA", "DSA", "DIFFIE_HELLMAN", "DH" })
	void isSizeBasedTrueForClassicalAlgorithms(String algorithm)
	{
		assertTrue(CliSupport.isSizeBased(KeyPairGeneratorAlgorithm.valueOf(algorithm)));
	}

	@ParameterizedTest
	@ValueSource(strings = { "X25519", "X448", "ML_KEM_768", "ML_DSA_65" })
	void isSizeBasedFalseForModernAlgorithms(String algorithm)
	{
		assertFalse(CliSupport.isSizeBased(KeyPairGeneratorAlgorithm.valueOf(algorithm)));
	}

	@Test
	void writePrivateAndPublicKeyPemToFiles(@TempDir File tempDir) throws Exception
	{
		KeyPair keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, 2048);
		File privateFile = new File(tempDir, "private.pem");
		File publicFile = new File(tempDir, "public.pem");

		CliSupport.writePrivateKeyPem(keyPair.getPrivate(), privateFile);
		CliSupport.writePublicKeyPem(keyPair.getPublic(), publicFile);

		assertTrue(Files.readString(privateFile.toPath()).contains("PRIVATE KEY"));
		assertTrue(Files.readString(publicFile.toPath()).contains("PUBLIC KEY"));
	}

	@Test
	void writePrivateAndPublicKeyPemToStdout() throws Exception
	{
		KeyPair keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, 2048);
		PrintStream originalOut = System.out;
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		System.setOut(new PrintStream(buffer, true, StandardCharsets.UTF_8));
		try
		{
			CliSupport.writePrivateKeyPem(keyPair.getPrivate(), null);
			CliSupport.writePublicKeyPem(keyPair.getPublic(), null);
		}
		finally
		{
			System.setOut(originalOut);
		}
		String printed = buffer.toString(StandardCharsets.UTF_8);
		assertTrue(printed.contains("PRIVATE KEY"));
		assertTrue(printed.contains("PUBLIC KEY"));
	}

	@Test
	void errorRendersTheMessage()
	{
		assertTrue(CliSupport.error("boom").contains("boom"));
	}
}
