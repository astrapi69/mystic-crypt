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
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
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
	 * An unencrypted PKCS#8 private key file, generated fresh for every run rather than committed.
	 * A checked-in private key - even a throwaway one that guards nothing - is indistinguishable
	 * from a leaked one to a secret scanner, and this file exists purely to be rejected by the
	 * reader, so its contents never need to be stable.
	 */
	@TempDir
	static Path temporaryDirectory;

	private static File unencryptedPkcs8KeyFile;

	@BeforeAll
	static void writeAnUnencryptedPkcs8Key() throws Exception
	{
		PrivateKey privateKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate();
		String base64 = Base64
			.getMimeEncoder(64, System.lineSeparator().getBytes(StandardCharsets.US_ASCII))
			.encodeToString(privateKey.getEncoded());
		Path keyFile = temporaryDirectory.resolve("pkcs8-unencrypted.pem");
		Files.writeString(keyFile, "-----BEGIN PRIVATE KEY-----" + System.lineSeparator() + base64
			+ System.lineSeparator() + "-----END PRIVATE KEY-----" + System.lineSeparator());
		unencryptedPkcs8KeyFile = keyFile.toFile();
	}

	/**
	 * A scenario for a private key file that can not be resolved
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param privateKeyFile
	 *            supplies the private key file, resolved per test rather than up front so that a
	 *            case may point at a file that is only written once the test class starts
	 */
	record UnresolvableCase(String description, Supplier<File> privateKeyFile) {
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
		return Stream.of(
			new UnresolvableCase("password protected private key",
				() -> testResource("pem/test.key.pem")),
			new UnresolvableCase("private key file that does not exist",
				() -> testResource("pem/this-file-does-not-exist.pem")),
			new UnresolvableCase("unencrypted PKCS#8 key the reader can not turn into a key pair",
				() -> unencryptedPkcs8KeyFile));
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
		Optional<String> resolved = PrivateKeyBruteForceProcessor
			.resolvePassword(testCase.privateKeyFile().get(), new BruteForceProcessor(ALPHABET, 1));

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
	 * {@link PrivateKeyBruteForceProcessor#resolvePassword(File, BruteForceProcessor)}, an
	 * unencrypted PKCS#8 key (header {@code BEGIN PRIVATE KEY}) is not password protected, so the
	 * method enters its resolution path, yet the reader rejects it with a {@code PEMException} on
	 * every attempt. The previous implementation treated that as a wrong-password signal and looped
	 * forever over an ever growing attempt space; this test hangs against the old code (hence the
	 * preemptive timeout) and passes against the fix, which treats the unparseable key as a
	 * terminal error and answers an empty optional.
	 */
	@Test
	public void resolvePassword_terminatesForAnUnencryptedPkcs8KeyInsteadOfHanging()
	{
		Optional<String> resolved = assertTimeoutPreemptively(Duration.ofSeconds(10),
			() -> PrivateKeyBruteForceProcessor.resolvePassword(unencryptedPkcs8KeyFile,
				new BruteForceProcessor(ALPHABET, 1)));

		assertFalse(resolved.isPresent());
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
