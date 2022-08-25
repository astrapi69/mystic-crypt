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
package io.github.astrapi69.mystic.crypt.key;

import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.security.PublicKey;

import io.github.astrapi69.mystic.crypt.key.PublicKeyHexEncryptor;
import org.testng.annotations.Test;

import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.file.search.PathFinder;

/**
 * The unit test class for the class {@link PublicKeyHexEncryptor}
 */
public class PublicKeyHexEncryptorTest
{

	/**
	 * Test method for {@link PublicKeyHexEncryptor} constructors
	 *
	 * @throws Exception
	 *             is thrown if any error occurs
	 */
	@Test
	public void testConstructors() throws Exception
	{
		PublicKey publicKey;
		File publickeyDerDir;
		File publickeyDerFile;
		PublicKeyHexEncryptor encryptor;
		String encrypted;

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		publickeyDerFile = new File(publickeyDerDir, "public.der");
		publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);
		encryptor = new PublicKeyHexEncryptor(publicKey);
		assertNotNull(encryptor);
		encrypted = encryptor.encrypt("foo");
		assertNotNull(encrypted);
	}
}
