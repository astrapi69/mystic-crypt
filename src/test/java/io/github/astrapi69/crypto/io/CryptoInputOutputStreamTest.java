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
package io.github.astrapi69.crypto.io;

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

import io.github.astrapi69.crypto.io.CryptoInputStream;
import io.github.astrapi69.crypto.io.CryptoOutputStream;
import org.testng.annotations.Test;

import io.github.astrapi69.crypto.core.AbstractStringDecryptor;
import io.github.astrapi69.crypto.hex.HexableDecryptor;
import io.github.astrapi69.crypto.hex.HexableEncryptor;
import de.alpharogroup.file.delete.DeleteFileExtensions;
import de.alpharogroup.file.read.ReadFileExtensions;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the classes {@link HexableEncryptor} and {@link CryptoInputStream} and
 * the classes {@link HexableDecryptor} and {@link CryptoOutputStream}
 */
public class CryptoInputOutputStreamTest
{

	/**
	 * Test method for
	 * {@link CryptoOutputStream#CryptoOutputStream(OutputStream, AbstractStringDecryptor)} for read
	 * and write to decrypted file with cipher IO
	 */
	@Test
	public void testCryptoOutputStream() throws Exception
	{
		String actual;
		String expected;
		File cryptDir;
		File toEncrypt;
		File encryptedFile;
		String key;
		HexableEncryptor encryptor;
		int c;
		File decryptedFile;
		HexableDecryptor decryptor;

		cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		toEncrypt = new File(cryptDir, "test.txt");
		encryptedFile = new File(cryptDir, "encryptedWithCryptoInputStream.txt");
		key = "D1D15ED36B887AF1";
		encryptor = new HexableEncryptor(key);

		try (InputStream fis = new FileInputStream(toEncrypt);
			InputStream cis = new CryptoInputStream(fis, encryptor);
			FileOutputStream out = new FileOutputStream(encryptedFile))
		{

			while ((c = cis.read()) != -1)
			{
				out.write(c);
			}
		}

		decryptedFile = new File(cryptDir, "decryptedWithCryptoOutputStream.txt");
		decryptor = new HexableDecryptor(key);

		try (OutputStream fileOutput = new FileOutputStream(decryptedFile);
			OutputStream cos = new CryptoOutputStream(fileOutput, decryptor);
			FileInputStream encryptedFis = new FileInputStream(encryptedFile))
		{

			while ((c = encryptedFis.read()) != -1)
			{
				cos.write(c);
			}
		}

		// Verify the enryption and decryption process by compare the content of
		// files...
		expected = ReadFileExtensions.readFromFile(toEncrypt);
		actual = ReadFileExtensions.readFromFile(decryptedFile);
		assertEquals(expected, actual);
		// clean up...
		DeleteFileExtensions.delete(encryptedFile);
		DeleteFileExtensions.delete(decryptedFile);
	}

}
