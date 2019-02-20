/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto.processors.bruteforce;

import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.util.Optional;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.reader.EncryptedPrivateKeyReader;
import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.file.search.PathFinder;
import lombok.NonNull;
import lombok.extern.java.Log;

/**
 * The unit test class for the class {@link BruteForceProcessor}
 */
@Log
public class PrivateKeyBruteForceProcessorTest
{

	/**
	 * Test method for test the class {@link BruteForceProcessor}.
	 *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test(enabled = true)
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
		encryptedPrivateKeyFile = new File(pemDir, "test.key");


		Security.addProvider(new BouncyCastleProvider());

		possibleCharacters = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
				'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

		processor = new BruteForceProcessor(possibleCharacters, 1);
		start = System.currentTimeMillis();
		Optional<String> resolvePassword = resolvePassword(encryptedPrivateKeyFile, processor);
		end = System.currentTimeMillis();

		elapsedMilliSeconds = end - start;

		log.info("************************************************************");
		log.info("************************************************************");
		log.info("*                 Password found!                          *");
		log.info("************************************************************");
		log.info("Needed milliseconds for crack the password with brute force attack: "
			+ elapsedMilliSeconds);
		log.info("************************************************************");
		log.info("*    The wanted password is the following:'" + resolvePassword.get() + "'");
		log.info("************************************************************");
		log.info("************************************************************");
	}

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
		@NonNull BruteForceProcessor processor)
	{
		Optional<String> optionalPassword = Optional.empty();
		try
		{
			boolean isPasswordProtected = PrivateKeyReader
				.isPrivateKeyPasswordProtected(privateKeyFile);

			if (!isPasswordProtected)
			{


				String attempt;
				attempt = processor.getCurrentAttempt();
				Security.addProvider(new BouncyCastleProvider());
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

}