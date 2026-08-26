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
import java.io.IOException;
import java.nio.file.Files;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Unit tests for the {@code checksum} subcommand, asserting the well-known digests of the string
 * "abc" for each algorithm, and the keyed answer next to them.
 * <p>
 * The value is the first whitespace-separated field of the output, as with {@code sha256sum}, and
 * the rest of the line says which of the two questions was answered.
 */
class ChecksumCommandTest extends AbstractCliTest
{

	private static File abcFile(File tempDir) throws IOException
	{
		File abc = new File(tempDir, "abc.txt");
		Files.writeString(abc.toPath(), "abc");
		return abc;
	}

	private String value()
	{
		return out.strip().split("\\s+")[0];
	}

	@ParameterizedTest
	@CsvSource({ "MD5,900150983cd24fb0d6963f7d28e17f72",
			"SHA-1,a9993e364706816aba3e25717850c26c9cd0d89d",
			"SHA-256,ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
			"SHA-512,ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" })
	void computesKnownDigestOfAbc(String algorithm, String expected, @TempDir File tempDir)
		throws Exception
	{
		File abc = abcFile(tempDir);

		assertEquals(0, run("checksum", "--algorithm", algorithm, abc.getAbsolutePath()));

		assertEquals(expected, value());
		assertTrue(out.contains(algorithm + " digest"),
			"the line must say which question was answered, but was: '" + out + "'");
	}

	@Test
	void defaultAlgorithmIsSha256(@TempDir File tempDir) throws Exception
	{
		File abc = abcFile(tempDir);

		assertEquals(0, run("checksum", abc.getAbsolutePath()));

		assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", value());
	}

	@Test
	void unknownAlgorithmFails(@TempDir File tempDir) throws Exception
	{
		File abc = abcFile(tempDir);

		assertEquals(2, run("checksum", "--algorithm", "NOPE-1", abc.getAbsolutePath()));
		assertTrue(err.contains("unknown digest algorithm"), "stderr was: '" + err + "'");
	}

	/** RFC 4231 test case 1, so the keyed answer is pinned to a published vector. */
	@Test
	void computesTheRfc4231HmacSha256Vector(@TempDir File tempDir) throws Exception
	{
		File data = new File(tempDir, "data.bin");
		Files.write(data.toPath(), "Hi There".getBytes(java.nio.charset.StandardCharsets.UTF_8));

		// the published key for case 1 is twenty bytes of 0x0b, which a key can carry through
		// standard input because it is not a line terminator
		String key = "\u000b".repeat(20);

		assertEquals(0,
			runWithStdin(key + "\n", "checksum", "--hmac", "--key-stdin", data.getAbsolutePath()),
			"stderr was: '" + err + "'");

		assertEquals("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", value(),
			"RFC 4231 case 1 for HMAC-SHA-256");
	}

	@Test
	void theKeyedAnswerSaysItIsKeyedAndDiffersFromThePlainDigest(@TempDir File tempDir)
		throws Exception
	{
		File abc = abcFile(tempDir);

		assertEquals(0, run("checksum", abc.getAbsolutePath()));
		String plain = value();

		assertEquals(0, run("checksum", "--hmac", "--key", "the key", abc.getAbsolutePath()));
		String keyed = value();

		assertNotEquals(plain, keyed, "a keyed answer must not equal the plain digest");
		assertTrue(out.contains("HmacSHA256 keyed digest"),
			"the line must say the answer is keyed, but was: '" + out + "'");
	}

	@Test
	void adifferentKeyGivesADifferentAnswer(@TempDir File tempDir) throws Exception
	{
		File abc = abcFile(tempDir);

		assertEquals(0, run("checksum", "--hmac", "--key", "one key", abc.getAbsolutePath()));
		String first = value();
		assertEquals(0, run("checksum", "--hmac", "--key", "another key", abc.getAbsolutePath()));

		assertNotEquals(first, value(),
			"that is the whole point of the keyed answer: without the key it cannot be reproduced");
	}

	@Test
	void aDigestNameUnderHmacSaysWhatToDoInstead(@TempDir File tempDir) throws Exception
	{
		File abc = abcFile(tempDir);

		assertEquals(2,
			run("checksum", "--hmac", "-a", "SHA-256", "--key", "k", abc.getAbsolutePath()));

		assertTrue(err.contains("drop --hmac"),
			"the message must say how to get the plain digest, but was: '" + err + "'");
	}

	@Test
	void aMissingKeyUnderHmacNamesTheOptions(@TempDir File tempDir) throws Exception
	{
		File abc = abcFile(tempDir);

		assertEquals(2, run("checksum", "--hmac", abc.getAbsolutePath()));

		assertTrue(err.contains("--password") || err.contains("--key"),
			"the message must name how to pass the key, but was: '" + err + "'");
	}

	/**
	 * A password-based MAC exists under a JDK name but cannot take a plain key: SunJCE answers
	 * "Missing password" for HmacPBESHA1 given a SecretKeySpec. That is a different failure from an
	 * unknown algorithm and has to read differently.
	 */
	@Test
	void aMacThatCannotTakeAPlainKeySaysTheKeyWasRejected(@TempDir File tempDir) throws Exception
	{
		File abc = abcFile(tempDir);

		assertEquals(2,
			run("checksum", "--hmac", "-a", "HmacPBESHA1", "--key", "k", abc.getAbsolutePath()));

		assertTrue(err.contains("MAC key was rejected"),
			"the message must separate a rejected key from an unknown algorithm, but was: '" + err
				+ "'");
	}

	@Test
	void theCommandAnswersItsOwnHelp()
	{
		assertEquals(0, run("checksum", "--help"));
		assertTrue(out.contains("--hmac"), "stdout was: '" + out + "'");
	}
}
