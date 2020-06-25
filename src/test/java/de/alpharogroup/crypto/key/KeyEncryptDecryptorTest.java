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

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertTrue;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.KeyPairWithModeAndPaddingAlgorithm;
import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.crypto.key.reader.PublicKeyReader;
import de.alpharogroup.crypto.model.CryptModel;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link PublicKeyEncryptor} and the class
 * {@link PrivateKeyDecryptor}
 */
public class KeyEncryptDecryptorTest
{

	/**
	 * Test encrypt and decrypt with {@link PublicKeyEncryptor#encrypt(byte[])} and
	 * {@link PrivateKeyDecryptor#decrypt(byte[])} loaded from der files.
	 *
	 * @throws Exception
	 *             is thrown if any security exception occured.
	 */
	@Test
	public void testEncryptDecryptDerFiles() throws Exception
	{
		String actual;
		String expected;
		byte[] testBytes;
		File publickeyDerDir;
		File publickeyDerFile;
		File privatekeyDerFile;
		PrivateKey privateKey;
		PublicKey publicKey;
		CryptModel<Cipher, PublicKey, byte[]> encryptModel;
		CryptModel<Cipher, PrivateKey, byte[]> decryptModel;
		PublicKeyEncryptor encryptor;
		PrivateKeyDecryptor decryptor;
		byte[] encrypted;
		byte[] decrypted;

		expected = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";
		testBytes = expected.getBytes("UTF-8");

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "/der");
		publickeyDerFile = new File(publickeyDerDir, "public.der");
		privatekeyDerFile = new File(publickeyDerDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);

		encryptModel = CryptModel.<Cipher, PublicKey, byte[]> builder().key(publicKey)
			.algorithm(KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA1AndMGF1Padding)
			.build();

		decryptModel = CryptModel.<Cipher, PrivateKey, byte[]> builder().key(privateKey)
			.algorithm(KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA1AndMGF1Padding)
			.build();

		encryptor = new PublicKeyEncryptor(encryptModel);
		decryptor = new PrivateKeyDecryptor(decryptModel);

		encrypted = encryptor.encrypt(testBytes);

		decrypted = decryptor.decrypt(encrypted);

		actual = new String(decrypted, "UTF-8");
		assertEquals(actual, expected);
	}

	/**
	 * Test encrypt and decrypt with {@link PublicKeyEncryptor#encrypt(byte[])} and
	 * {@link PrivateKeyDecryptor#decrypt(byte[])} loaded from pem files.
	 *
	 * @throws Exception
	 *             is thrown if any security exception occured.
	 */
	@Test
	public void testEncryptDecryptPemFiles() throws Exception
	{
		String actual;
		String expected;
		byte[] testBytes;
		File keyPemDir;
		File publickeyPemFile;
		File privatekeyPemFile;
		PrivateKey privateKey;
		PublicKey publicKey;
		CryptModel<Cipher, PublicKey, byte[]> encryptModel;
		CryptModel<Cipher, PrivateKey, byte[]> decryptModel;
		PublicKeyEncryptor encryptor;
		PrivateKeyDecryptor decryptor;
		byte[] encrypted;
		byte[] decrypted;

		expected = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";
		testBytes = expected.getBytes("UTF-8");

		keyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "/pem");
		publickeyPemFile = new File(keyPemDir, "public.pem");
		privatekeyPemFile = new File(keyPemDir, "private.pem");

		Security.addProvider(new BouncyCastleProvider());
		privateKey = PrivateKeyReader.readPemPrivateKey(privatekeyPemFile);

		publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		encryptModel = CryptModel.<Cipher, PublicKey, byte[]> builder().key(publicKey)
			.algorithm(KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA256AndMGF1Padding)
			.build();

		decryptModel = CryptModel.<Cipher, PrivateKey, byte[]> builder().key(privateKey)
			.algorithm(KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA256AndMGF1Padding)
			.build();

		encryptor = new PublicKeyEncryptor(encryptModel);
		decryptor = new PrivateKeyDecryptor(decryptModel);

		encrypted = encryptor.encrypt(testBytes);

		decrypted = decryptor.decrypt(encrypted);

		actual = new String(decrypted, "UTF-8");
		assertTrue("String before encryption is not equal after decryption.",
			expected.equals(actual));
		for (int i = 0; i < 100; i++)
		{
			encrypted = encryptor.encrypt(testBytes);
			decrypted = decryptor.decrypt(encrypted);

			actual = new String(decrypted, "UTF-8");
			assertTrue("String before encryption is not equal after decryption.",
				expected.equals(actual));
			assertEquals(actual, expected);
		}
	}

}
