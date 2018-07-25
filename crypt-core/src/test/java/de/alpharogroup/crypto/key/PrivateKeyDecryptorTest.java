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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.crypto.model.CryptModel;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link PrivateKeyDecryptor}
 */
public class PrivateKeyDecryptorTest
{

	/**
	 * Test method for {@link PrivateKeyDecryptor} constructors
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public final void testConstructors() throws Exception 
	{
		PrivateKey privateKey;
		CryptModel<Cipher, PrivateKey> decryptModel;
		String test;
		byte[] testBytes;
		
		test = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";
		testBytes = test.getBytes("UTF-8");
		
		final File derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		final File privatekeyDerFile = new File(derDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		decryptModel = CryptModel.<Cipher, PrivateKey> builder().key(privateKey).build();
		PublicKeyEncryptor encryptor = new PublicKeyEncryptor(CryptModel.<Cipher, PublicKey> builder().key(PrivateKeyExtensions.generatePublicKey(privateKey)).build());
		
		PrivateKeyDecryptor decryptor = new PrivateKeyDecryptor(decryptModel);
		assertNotNull(decryptor);
		byte[] decrypted = decryptor.decrypt(encryptor.encrypt(testBytes));
		assertNotNull(decrypted);
		assertEquals(new String(decrypted, "UTF-8"), test);
	}
	
}
