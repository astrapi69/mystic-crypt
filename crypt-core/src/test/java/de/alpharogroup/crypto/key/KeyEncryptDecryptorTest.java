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
import java.security.Security;

import javax.crypto.Cipher;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.KeyPairWithModeAndPaddingAlgorithm;
import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.crypto.key.reader.PublicKeyReader;
import de.alpharogroup.crypto.model.CryptModel;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link PublicKeyEncryptor} and the class
 * {@link PrivateKeyDecryptor}.
 */
public class KeyEncryptDecryptorTest
{

	/** The Constant logger. */
	private static final Logger logger = Logger.getLogger(KeyEncryptDecryptorTest.class.getName());

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
		final String test = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";
		final byte[] testBytes = test.getBytes("UTF-8");

		final File publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		final File publickeyDerFile = new File(publickeyDerDir, "public.der");
		final File privatekeyDerFile = new File(publickeyDerDir, "private.der");

		final PrivateKey privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		final PublicKey publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);

		final CryptModel<Cipher, PublicKey> encryptModel = CryptModel.<Cipher, PublicKey> builder()
			.key(publicKey)
			.algorithm(KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA1AndMGF1Padding)
			.build();

		final CryptModel<Cipher, PrivateKey> decryptModel = CryptModel
			.<Cipher, PrivateKey> builder().key(privateKey)
			.algorithm(KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA1AndMGF1Padding)
			.build();

		final PublicKeyEncryptor encryptor = new PublicKeyEncryptor(encryptModel);
		final PrivateKeyDecryptor decryptor = new PrivateKeyDecryptor(decryptModel);


		final byte[] encrypted = encryptor.encrypt(testBytes);

		final byte[] decrypted = decryptor.decrypt(encrypted);

		final String decryptedString = new String(decrypted, "UTF-8");
		AssertJUnit.assertTrue("String before encryption is not equal after decryption.",
			test.equals(decryptedString));
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
		final String test = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";
		final byte[] testBytes = test.getBytes("UTF-8");

		final File keyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File publickeyPemFile = new File(keyPemDir, "public.pem");
		final File privatekeyPemFile = new File(keyPemDir, "private.pem");

		Security.addProvider(new BouncyCastleProvider());
		final PrivateKey privateKey = PrivateKeyReader.readPemPrivateKey(privatekeyPemFile);

		final PublicKey publicKey = PublicKeyReader.readPemPublicKey(publickeyPemFile);

		final CryptModel<Cipher, PublicKey> encryptModel = CryptModel.<Cipher, PublicKey> builder()
			.key(publicKey)
			.algorithm(KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA256AndMGF1Padding)
			.build();

		final CryptModel<Cipher, PrivateKey> decryptModel = CryptModel
			.<Cipher, PrivateKey> builder().key(privateKey)
			.algorithm(KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA256AndMGF1Padding)
			.build();

		final PublicKeyEncryptor encryptor = new PublicKeyEncryptor(encryptModel);
		final PrivateKeyDecryptor decryptor = new PrivateKeyDecryptor(decryptModel);


		byte[] encrypted = encryptor.encrypt(testBytes);

		byte[] decrypted = decryptor.decrypt(encrypted);

		String decryptedString = new String(decrypted, "UTF-8");
		logger.debug(decryptedString);
		AssertJUnit.assertTrue("String before encryption is not equal after decryption.",
			test.equals(decryptedString));
		for (int i = 0; i < 100; i++)
		{
			encrypted = encryptor.encrypt(testBytes);
			decrypted = decryptor.decrypt(encrypted);

			decryptedString = new String(decrypted, "UTF-8");
			AssertJUnit.assertTrue("String before encryption is not equal after decryption.",
				test.equals(decryptedString));
			logger.debug(decryptedString);
		}
	}

}
