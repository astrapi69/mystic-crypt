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
package io.github.astrapi69.crypto.processors.bruteforce;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertTrue;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.Test;

import de.alpharogroup.file.search.PathFinder;
import io.github.astrapi69.crypto.key.reader.EncryptedPrivateKeyReader;
import io.github.astrapi69.crypto.key.reader.PrivateKeyReader;

/**
 * The unit test class for the class {@link BruteForceProcessor}
 */
public class PrivateKeyBruteForceProcessorTest
{

	private static final Logger log = Logger
		.getLogger(PrivateKeyBruteForceProcessorTest.class.getName());

	/**
	 * Resolve the password from the given private key file. If no password is set an empty Optional
	 * will be returned.
	 *
	 * @param privateKeyFile
	 *            the private key file
	 * @param processor
	 *            the processor
	 * @return the optional
	 */
	public static Optional<String> resolvePassword(File privateKeyFile,
		BruteForceProcessor processor)
	{
		Objects.requireNonNull(processor);
		Optional<String> optionalPassword = Optional.empty();
		try
		{
			Security.addProvider(new BouncyCastleProvider());
			boolean isPasswordProtected = PrivateKeyReader
				.isPrivateKeyPasswordProtected(privateKeyFile);

			if (isPasswordProtected)
			{
				String attempt;
				attempt = processor.getCurrentAttempt();
				while (true)
				{
					try
					{
						EncryptedPrivateKeyReader.getKeyPair(privateKeyFile, attempt);
						optionalPassword = Optional.of(attempt);
						break;
					}
					catch (IOException e)
					{
						attempt = processor.getCurrentAttempt();
						processor.increment();
					}
				}
			}
		}
		catch (IOException ex)
		{
			return optionalPassword;
		}
		return optionalPassword;
	}

	/**
	 * Test method for test the class {@link BruteForceProcessor}
	 */
	@Test(enabled = false)
	public void testPrivateKeyWithPassword()
	{
		File pemDir;
		File encryptedPrivateKeyFile;
		char[] possibleCharacters;
		BruteForceProcessor processor;
		long start;
		long end;
		long elapsedMilliSeconds;

		pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		encryptedPrivateKeyFile = new File(pemDir, "test.key.pem");

		possibleCharacters = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
				'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

		processor = new BruteForceProcessor(possibleCharacters, 1);
		start = System.currentTimeMillis();
		Optional<String> resolvePassword = resolvePassword(encryptedPrivateKeyFile, processor);
		end = System.currentTimeMillis();

		elapsedMilliSeconds = end - start;
		assertTrue(resolvePassword.isPresent());
		String expected = "bosco";
		String actual = resolvePassword.get();
		assertEquals(expected, actual);
		log.info("Needed milliseconds for crack the password with brute force attack: "
			+ elapsedMilliSeconds);
	}

}
