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
package io.github.astrapi69.crypto.key;

import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.security.PublicKey;

import javax.crypto.Cipher;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.file.delete.DeleteFileExtensions;
import de.alpharogroup.file.search.PathFinder;
import io.github.astrapi69.crypto.key.reader.PublicKeyReader;
import io.github.astrapi69.crypto.model.CryptModel;

/**
 * The unit test class for the class {@link PublicKeyFileEncryptor}
 */
public class PublicKeyFileEncryptorTest
{

	File cryptDir;
	File encrypted;
	File toEncrypt;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeMethod
	protected void setUp()
	{
		cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		toEncrypt = new File(cryptDir, "test.txt");
	}

	/**
	 * Test method for {@link PublicKeyFileEncryptor#encrypt(File)}
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test public void testEncrypt() throws Exception
	{
		PublicKey publicKey;
		PublicKeyFileEncryptor encryptor;
		CryptModel<Cipher, PublicKey, String> encryptModel;
		File publickeyDerDir;
		File publickeyDerFile;

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		publickeyDerFile = new File(publickeyDerDir, "public.der");
		publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);

		encryptModel = CryptModel.<Cipher, PublicKey, String> builder().key(publicKey).build();

		encryptor = new PublicKeyFileEncryptor(encryptModel);
		assertNotNull(encryptor);

		encrypted = encryptor.encrypt(toEncrypt);
		assertNotNull(encrypted);
		// clean up...
		DeleteFileExtensions.delete(encrypted);
	}
}
