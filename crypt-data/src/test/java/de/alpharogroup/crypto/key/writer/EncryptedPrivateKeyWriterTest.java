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
package de.alpharogroup.crypto.key.writer;

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.security.PrivateKey;

import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.key.reader.EncryptedPrivateKeyReader;
import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link EncryptedPrivateKeyWriter}.
 */
public class EncryptedPrivateKeyWriterTest
{

	/**
	 * Test encrypt private key with password private key file string.
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testEncryptPrivateKeyWithPasswordPrivateKeyFileString() throws Exception
	{
		PrivateKey expected;
		PrivateKey actual;
		final File derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		final File encryptedPrivateKeyFile = new File(derDir, "encryptedPrivate.der");

		final PrivateKey readedPrivateKey = PrivateKeyReader
			.readPrivateKey(PathFinder.getSrcTestResourcesDir(), "der", "private.der");
		final String password = "secret";
		EncryptedPrivateKeyWriter.encryptPrivateKeyWithPassword(readedPrivateKey,
			encryptedPrivateKeyFile, password);

		final PrivateKey decryptedPrivateKey = EncryptedPrivateKeyReader
			.decryptPasswordProtectedPrivateKey(encryptedPrivateKeyFile, password,
				KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		expected = readedPrivateKey;
		actual = decryptedPrivateKey;
		assertEquals(expected, actual);
	}

}
