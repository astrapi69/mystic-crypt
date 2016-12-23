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


import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.provider.SecurityProvider;
import de.alpharogroup.file.search.PathFinder;

/**
 * Test class for {@link PublicKeyHexEncryptor} and {@link PrivateKeyHexDecryptor}.
 */
public class KeyHexEncryptDecryptorTest
{

	/**
	 * Test encrypt and decrypt with {@link PublicKeyHexEncryptor#encrypt(String)} and
	 * {@link PrivateKeyHexDecryptor#decrypt(String)} loaded from pem files.
	 *
	 * @throws Exception
	 *             is thrown if any security exception occured.
	 */
	@Test(enabled = true)
	public void testEncryptDecryptPemFiles() throws Exception
	{
		final String test = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";
		System.out.println("String before encryption:");
		System.out.println(test);

		final File publickeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File publickeyPemFile = new File(publickeyPemDir, "public.pem");
		final File privatekeyPemFile = new File(publickeyPemDir, "private.pem");

		final PrivateKey privateKey = KeyExtensions.readPemPrivateKey(privatekeyPemFile,
			SecurityProvider.BC);

		final PublicKey publicKey = KeyExtensions.readPemPublicKey(publickeyPemFile,
			SecurityProvider.BC);

		final PublicKeyHexEncryptor encryptor = new PublicKeyHexEncryptor(publicKey);

		final String encrypted = encryptor.encrypt(test);

		System.out.println("String after encryption:");
		System.out.println(encrypted);
		final PrivateKeyHexDecryptor decryptor = new PrivateKeyHexDecryptor(privateKey);
		final String decryted = decryptor.decrypt(encrypted);
		System.out.println("String after decryption:");
		System.out.println(decryted);
		AssertJUnit.assertTrue("String before encryption is not equal after decryption.",
			test.equals(decryted));
	}

	/**
	 * Test encrypt and decrypt with {@link PublicKeyHexEncryptor#encrypt(String)} and
	 * {@link PrivateKeyHexDecryptor#decrypt(String)} loaded from pem files.
	 *
	 * @throws Exception
	 *             is thrown if any security exception occured.
	 */
	@Test(enabled = true)
	public void testEncryptDecrypt() throws Exception
	{
		final String test = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";

		final File publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		final File publickeyDerFile = new File(publickeyDerDir, "public.der");
		final File privatekeyDerFile = new File(publickeyDerDir, "private.der");

		final PrivateKey privateKey = KeyExtensions.readPrivateKey(privatekeyDerFile);

		final PublicKey publicKey = KeyExtensions.readPublicKey(publickeyDerFile);

		final PublicKeyHexEncryptor encryptor = new PublicKeyHexEncryptor(publicKey);

		final String encrypted = encryptor.encrypt(test);

		System.out.println("String after encryption:");
		System.out.println(encrypted);
		final PrivateKeyHexDecryptor decryptor = new PrivateKeyHexDecryptor(privateKey);
		final String decryted = decryptor.decrypt(encrypted);
		AssertJUnit.assertTrue("String before encryption is not equal after decryption.",
			test.equals(decryted));
	}

}
