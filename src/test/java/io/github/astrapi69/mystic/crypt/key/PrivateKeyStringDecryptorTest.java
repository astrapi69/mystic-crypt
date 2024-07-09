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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.file.read.ReadFileExtensions;
import io.github.astrapi69.file.search.PathFinder;

public class PrivateKeyStringDecryptorTest
{


	/**
	 * Test to encrypt with {@link PrivateKeyStringDecryptor#decrypt(byte[])}
	 *
	 * @throws Exception
	 *             is thrown if the encryption or the decryption fails
	 */
	@Test
	public void testConstructorWithPrivateKey() throws Exception
	{
		String actual;
		String expected;
		String xmlString;
		PublicKeyStringEncryptor encryptor;
		PublicKey publicKey;
		File publickeyDerDir;
		File publickeyDerFile;
		File xml;
		byte[] encrypted;
		PrivateKey privateKey;
		File derDir;
		File privatekeyDerFile;
		PrivateKeyStringDecryptor decryptor;

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		publickeyDerFile = new File(publickeyDerDir, "public.der");
		publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);
		xml = PathFinder.getRelativePath(PathFinder.getSrcTestResourcesDir(), "xml", "company.xml");
		xmlString = ReadFileExtensions.fromFile(xml);
		expected = xmlString;

		encryptor = new PublicKeyStringEncryptor(publicKey);
		assertNotNull(encryptor);
		encrypted = encryptor.encrypt(xmlString);
		assertNotNull(encrypted);


		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privatekeyDerFile = new File(derDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		decryptor = new PrivateKeyStringDecryptor(privateKey);

		String decrypted = decryptor.decrypt(encrypted);
		actual = decrypted;
		assertEquals(expected, actual);
	}
}