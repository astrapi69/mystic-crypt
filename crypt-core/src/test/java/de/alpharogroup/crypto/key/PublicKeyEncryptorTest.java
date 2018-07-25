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
package de.alpharogroup.crypto.key;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.security.PublicKey;

import javax.crypto.Cipher;

import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.reader.PublicKeyReader;
import de.alpharogroup.crypto.model.CryptModel;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link PublicKeyEncryptor}
 */
public class PublicKeyEncryptorTest
{

	/**
	 * Test method for {@link PublicKeyEncryptor} constructors
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public final void testConstructors() throws Exception
	{
		PublicKey publicKey;
		PublicKeyEncryptor encryptor;
		CryptModel<Cipher, PublicKey> encryptModel;
		final File publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		final File publickeyDerFile = new File(publickeyDerDir, "public.der");
		publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);

		encryptModel = CryptModel.<Cipher, PublicKey> builder().key(publicKey).build();

		encryptor = new PublicKeyEncryptor(encryptModel);
		assertNotNull(encryptor);

		byte[] encrypted = encryptor.encrypt("foo".getBytes("UTF-8"));
		assertNotNull(encrypted);
	}
}
