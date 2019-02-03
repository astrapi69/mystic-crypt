/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto.io;

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.testng.annotations.Test;

import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.algorithm.SunJCEAlgorithm;
import de.alpharogroup.crypto.factories.CipherFactory;
import de.alpharogroup.crypto.model.CryptModel;
import de.alpharogroup.file.delete.DeleteFileExtensions;
import de.alpharogroup.file.read.ReadFileExtensions;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the classes {@link CryptoCipherInputStream} and the classes
 * {@link CryptoCipherOutputStream}
 */
public class CryptoCipherInputOutputStreamTest
{

	/**
	 * Test read and write to decrypted file with cipher IO
	 *
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	@Test
	public void testReadAndWriteToDecryptedFileWithCipherIO()
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, IOException
	{
		String actual;
		String expected;
		String privateKey;
		final File cryptDir;
		final File toEncrypt;
		CryptModel<Cipher, String> encryptorModel;
		Cipher encryptorCipher;
		File encryptedFile;
		int c;
		File outputDecrypted;
		CryptModel<Cipher, String> decryptorModel;
		Cipher decryptorCipher;
		// new scenario...
		privateKey = "D1D15ED36B887AF1";
		cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		toEncrypt = new File(cryptDir, "test.txt");
		encryptedFile = new File(cryptDir, "encrypted.txt");

		encryptorModel = CryptModel.<Cipher, String> builder().key(privateKey)
			.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).salt(CryptConst.SALT).iterationCount(19)
			.operationMode(Cipher.ENCRYPT_MODE).build();

		encryptorCipher = CipherFactory.newCipher(encryptorModel);

		try (InputStream fis = new FileInputStream(toEncrypt);
			CryptoCipherInputStream cis = new CryptoCipherInputStream(fis, encryptorCipher);
			FileOutputStream out = new FileOutputStream(encryptedFile))
		{
			while ((c = cis.read()) != -1)
			{
				out.write(c);
			}
		}

		outputDecrypted = new File(cryptDir, "decrypted.txt");
		decryptorModel = encryptorModel.toBuilder().operationMode(Cipher.DECRYPT_MODE).build();

		decryptorCipher = CipherFactory.newCipher(decryptorModel);

		try (FileOutputStream decryptedOut = new FileOutputStream(outputDecrypted);
			CryptoCipherOutputStream cos = new CryptoCipherOutputStream(decryptedOut,
				decryptorCipher);
			FileInputStream encryptedFis = new FileInputStream(encryptedFile))
		{

			while ((c = encryptedFis.read()) != -1)
			{
				cos.write(c);
			}
		}
		// Verify the enryption and decryption process by compare the content of files...
		expected = ReadFileExtensions.readFromFile(toEncrypt);
		actual = ReadFileExtensions.readFromFile(outputDecrypted);
		assertEquals(expected, actual);
		// clean up...
		DeleteFileExtensions.delete(encryptedFile);
		DeleteFileExtensions.delete(outputDecrypted);

	}

}
