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

import java.io.File;
import java.nio.file.Files;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Unit tests for the {@code checksum} subcommand, asserting the well-known digests of the string
 * "abc" for each algorithm.
 */
class ChecksumCommandTest extends AbstractCliTest
{

	@ParameterizedTest
	@CsvSource({ "MD5,900150983cd24fb0d6963f7d28e17f72",
			"SHA-1,a9993e364706816aba3e25717850c26c9cd0d89d",
			"SHA-256,ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
			"SHA-512,ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" })
	void computesKnownDigestOfAbc(String algorithm, String expected, @TempDir File tempDir)
		throws Exception
	{
		File abc = new File(tempDir, "abc.txt");
		Files.writeString(abc.toPath(), "abc");
		assertEquals(0, run("checksum", "--algorithm", algorithm, abc.getAbsolutePath()));
		assertEquals(expected, out.strip());
	}

	@Test
	void defaultAlgorithmIsSha256(@TempDir File tempDir) throws Exception
	{
		File abc = new File(tempDir, "abc.txt");
		Files.writeString(abc.toPath(), "abc");
		assertEquals(0, run("checksum", abc.getAbsolutePath()));
		assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
			out.strip());
	}

	@Test
	void unknownAlgorithmFails(@TempDir File tempDir) throws Exception
	{
		File abc = new File(tempDir, "abc.txt");
		Files.writeString(abc.toPath(), "abc");
		assertNotEquals(0, run("checksum", "--algorithm", "NOPE-1", abc.getAbsolutePath()));
	}
}
