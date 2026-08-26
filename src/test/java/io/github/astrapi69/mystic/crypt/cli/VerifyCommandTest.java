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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for the {@code verify} subcommand: exit code 0 = matches, 1 = does not match, 2 = the
 * hash belongs to no algorithm this tool knows.
 * <p>
 * {@code verify} takes no {@code --algorithm}: every encoding says what produced it, and reading it
 * from the hash removes the way of getting it wrong.
 */
class VerifyCommandTest extends AbstractCliTest
{

	private String hash(String algorithm, String password)
	{
		assertEquals(0, run("hash", "--algorithm", algorithm, "--password", password),
			"hashing with " + algorithm + " failed, stderr was: '" + err + "'");
		return out.strip();
	}

	@ParameterizedTest
	@ValueSource(strings = { "argon2id", "pbkdf2", "bcrypt", "scrypt" })
	void aCorrectPasswordVerifiesWithoutBeingToldTheAlgorithm(String algorithm)
	{
		String hash = hash(algorithm, "the-secret");

		assertEquals(0, run("verify", "--hash", hash, "--password", "the-secret"),
			"stderr was: '" + err + "'");
		assertTrue(out.contains("matches"), "stdout was: '" + out + "'");
	}

	@ParameterizedTest
	@ValueSource(strings = { "argon2id", "pbkdf2", "bcrypt", "scrypt" })
	void aWrongPasswordDoesNotVerify(String algorithm)
	{
		String hash = hash(algorithm, "the-secret");

		assertEquals(1, run("verify", "--hash", hash, "--password", "wrong"));
		assertTrue(out.contains("does not match"), "stdout was: '" + out + "'");
	}

	/**
	 * The encoding each algorithm writes, which is what makes the detection possible. The bcrypt
	 * revision here is {@code 2y}, which is what this library's hasher actually produces; hashes
	 * written as {@code 2a} and {@code 2b} are the same construction and are recognised too.
	 */
	@ParameterizedTest
	@CsvSource({ "argon2id, $argon2id$, ARGON2ID", "pbkdf2, $pbkdf2-sha256$, PBKDF2",
			"bcrypt, $2y$, BCRYPT", "scrypt, $scrypt$, SCRYPT" })
	void eachAlgorithmWritesItsOwnPrefixAndIsNamedBackOnVerifying(String algorithm, String prefix,
		String reportedFormat)
	{
		String hash = hash(algorithm, "the-secret");
		assertTrue(hash.startsWith(prefix),
			algorithm + " must encode as " + prefix + ", but was: '" + hash + "'");

		assertEquals(0, run("verify", "--hash", hash, "--password", "the-secret"));
		assertTrue(out.contains(reportedFormat),
			"the answer must name the algorithm it detected, but was: '" + out + "'");
	}

	@Test
	void aHashOfNoKnownAlgorithmIsAnErrorNotAMismatch()
	{
		int exitCode = run("verify", "--hash", "not-a-hash-of-anything", "--password", "whatever");

		assertEquals(2, exitCode,
			"an unreadable hash is not the negative answer, stderr was: '" + err + "'");
		assertTrue(err.contains("$argon2id$") && err.contains("$2a$"),
			"the message must list the encodings it knows, but was: '" + err + "'");
	}

	@Test
	void theAlgorithmOptionIsGoneSinceTheHashCarriesIt()
	{
		String hash = hash("pbkdf2", "the-secret");

		assertNotEquals(0,
			run("verify", "--algorithm", "pbkdf2", "--hash", hash, "--password", "the-secret"),
			"--algorithm must no longer be accepted on verify");
	}

	@Test
	void readsPasswordFromStdin()
	{
		String hash = hash("pbkdf2", "piped");

		assertEquals(0, runWithStdin("piped\n", "verify", "--hash", hash, "--password-stdin"));
	}

	@Test
	void twoHashesOfTheSamePasswordDifferBecauseOfTheSalt()
	{
		assertNotEquals(hash("scrypt", "same"), hash("scrypt", "same"),
			"a fresh salt per hash must make two hashes of the same password differ");
		assertNotEquals(hash("bcrypt", "same"), hash("bcrypt", "same"));
	}
}
