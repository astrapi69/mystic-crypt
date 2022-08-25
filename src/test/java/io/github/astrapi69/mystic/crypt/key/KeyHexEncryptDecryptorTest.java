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

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import io.github.astrapi69.mystic.crypt.key.PrivateKeyHexDecryptor;
import io.github.astrapi69.mystic.crypt.key.PublicKeyHexEncryptor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.file.search.PathFinder;

/**
 *
 * The unit test class for the encryption and decryption with the class
 * {@link PublicKeyHexEncryptor} and {@link PrivateKeyHexDecryptor}
 */
public class KeyHexEncryptDecryptorTest
{

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeMethod
	protected void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Test encrypt and decrypt with {@link PublicKeyHexEncryptor#encrypt(String)} and
	 * {@link PrivateKeyHexDecryptor#decrypt(String)} loaded from pem files
	 *
	 * @throws Exception
	 *             is thrown if the encryption or the decryption fails
	 */
	@Test(enabled = true)
	public void testEncryptDecrypt() throws Exception
	{

		String actual;
		String expected;
		File derDir;
		File publickeyDerFile;
		File privatekeyDerFile;
		PrivateKey privateKey;
		PublicKey publicKey;
		PublicKeyHexEncryptor encryptor;
		PrivateKeyHexDecryptor decryptor;
		String encrypted;

		expected = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "/der");
		publickeyDerFile = new File(derDir, "public.der");
		privatekeyDerFile = new File(derDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);

		encryptor = new PublicKeyHexEncryptor(publicKey);

		encrypted = encryptor.encrypt(expected);

		decryptor = new PrivateKeyHexDecryptor(privateKey);

		actual = decryptor.decrypt(encrypted);
		assertEquals(actual, expected);
	}

	/**
	 * Test encrypt and decrypt with {@link PublicKeyHexEncryptor#encrypt(String)} and
	 * {@link PrivateKeyHexDecryptor#decrypt(String)} loaded from pem files.
	 *
	 * @throws Exception
	 *             is thrown if the encryption or the decryption fails
	 */
	@Test(enabled = true)
	public void testEncryptDecryptPemFiles() throws Exception
	{
		String actual;
		String expected;
		File publickeyPemDir;
		File publickeyPemFile;
		File privatekeyPemFile;
		PrivateKey privateKey;
		PublicKey publicKey;
		PublicKeyHexEncryptor encryptor;
		PrivateKeyHexDecryptor decryptor;
		String encrypted;

		expected = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";

		publickeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		publickeyPemFile = new File(publickeyPemDir, "public.pem");
		privatekeyPemFile = new File(publickeyPemDir, "private.pem");

		privateKey = PrivateKeyReader.readPemPrivateKey(privatekeyPemFile);

		publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		encryptor = new PublicKeyHexEncryptor(publicKey);

		encrypted = encryptor.encrypt(expected);
		decryptor = new PrivateKeyHexDecryptor(privateKey);
		actual = decryptor.decrypt(encrypted);
		assertEquals(actual, expected);
	}

}
