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
package io.github.astrapi69.mystic.crypt.processor.bruteforce;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.Optional;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The unit test class for the class {@link PrivateKeyBruteForceProcessor}
 */
public class PrivateKeyBruteForceProcessorTest
{

	/** A tiny alphabet keeps the runtime of every test in this class in the millisecond range */
	private static final char[] ALPHABET = { 'a', 'b', 'c' };

	/**
	 * A scenario for a private key file that can not be resolved
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param privateKeyFileName
	 *            the relative name of the private key file below the test resources
	 */
	record UnresolvableCase(String description, String privateKeyFileName) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	private static File testResource(final String relativeFileName)
	{
		return new File(PathFinder.getSrcTestResourcesDir(), relativeFileName);
	}

	static Stream<UnresolvableCase> unresolvableCases()
	{
		return Stream.of(new UnresolvableCase("password protected private key", "pem/test.key.pem"),
			new UnresolvableCase("private key file that does not exist",
				"pem/this-file-does-not-exist.pem"));
	}

	/**
	 * Test method for
	 * {@link PrivateKeyBruteForceProcessor#resolvePassword(File, BruteForceProcessor)}, an empty
	 * optional is answered for a private key file whose password can not be resolved
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("unresolvableCases")
	public void resolvePassword_answersAnEmptyOptional(final UnresolvableCase testCase)
	{
		Optional<String> resolved = PrivateKeyBruteForceProcessor.resolvePassword(
			testResource(testCase.privateKeyFileName()), new BruteForceProcessor(ALPHABET, 1));

		assertFalse(resolved.isPresent());
	}

	/**
	 * Test method for
	 * {@link PrivateKeyBruteForceProcessor#resolvePassword(File, BruteForceProcessor)}, the
	 * password protected test key really is recognized as password protected, which is the reason
	 * why the method above answers an empty optional
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void resolvePassword_acceptsTheFirstAttemptForAKeyThatIsNotPasswordProtected()
		throws Exception
	{
		File privateKeyFile = testResource("pem/private.pem");
		BruteForceProcessor processor = new BruteForceProcessor(ALPHABET, 2);
		assertFalse(PrivateKeyReader.isPrivateKeyPasswordProtected(privateKeyFile));

		Optional<String> resolved = PrivateKeyBruteForceProcessor.resolvePassword(privateKeyFile,
			processor);

		assertTrue(resolved.isPresent());
		assertEquals("aa", resolved.get());
		assertEquals("aa", processor.getCurrentAttempt(), "no further attempt is needed");
	}

	/**
	 * Test method for
	 * {@link PrivateKeyBruteForceProcessor#resolvePassword(File, BruteForceProcessor)}
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void resolvePassword_theTestKeyIsRecognizedAsPasswordProtected() throws Exception
	{
		assertTrue(
			PrivateKeyReader.isPrivateKeyPasswordProtected(testResource("pem/test.key.pem")));
	}

	/**
	 * Test method for
	 * {@link PrivateKeyBruteForceProcessor#resolvePassword(File, BruteForceProcessor)}, the
	 * processor is mandatory
	 */
	@Test
	public void resolvePassword_withoutAProcessor_throwsANullPointerException()
	{
		File privateKeyFile = testResource("pem/test.key.pem");

		assertThrows(NullPointerException.class,
			() -> PrivateKeyBruteForceProcessor.resolvePassword(privateKeyFile, null));
	}

	/**
	 * Test method for
	 * {@link PrivateKeyBruteForceProcessor#resolvePassword(File, BruteForceProcessor)}, the given
	 * processor is not consumed when the private key file is password protected
	 */
	@Test
	public void resolvePassword_leavesTheProcessorUntouchedForAProtectedPrivateKey()
	{
		BruteForceProcessor processor = new BruteForceProcessor(ALPHABET, 1);

		PrivateKeyBruteForceProcessor.resolvePassword(testResource("pem/test.key.pem"), processor);

		assertEquals("a", processor.getCurrentAttempt());
	}
}
