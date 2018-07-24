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
import java.io.InputStream;
import java.io.OutputStream;

import org.testng.annotations.Test;

import de.alpharogroup.crypto.core.AbstractStringDecryptor;
import de.alpharogroup.crypto.hex.HexableDecryptor;
import de.alpharogroup.crypto.hex.HexableEncryptor;
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

		final File cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		final File toEncrypt = new File(cryptDir, "test.txt");

		final InputStream fis = new FileInputStream(toEncrypt);

		final String key = "D1D15ED36B887AF1";

		final HexableEncryptor encryptor = new HexableEncryptor(key);

		InputStream cis = new CryptoInputStream(fis, encryptor);

		final File encryptedFile = new File(cryptDir, "encryptedWithCryptoInputStream.txt");


		final FileOutputStream out = new FileOutputStream(encryptedFile);

		int c;

		while ((c = cis.read()) != -1)
		{
			out.write(c);
		}

		cis.close();
		out.close();


		final File decryptedFile = new File(cryptDir, "decryptedWithCryptoOutputStream.txt");

		final HexableDecryptor decryptor = new HexableDecryptor(key);
		OutputStream fileOutput = new FileOutputStream(decryptedFile);
		OutputStream cos = new CryptoOutputStream(fileOutput, decryptor);

		final FileInputStream encryptedFis = new FileInputStream(encryptedFile);

		while ((c = encryptedFis.read()) != -1)
		{
			cos.write(c);
		}

		encryptedFis.close();
		cos.close();

		// Verify the enryption and decryption process by compare the content of files...

		String expected = ReadFileExtensions.readFromFile(toEncrypt);
		String actual = ReadFileExtensions.readFromFile(decryptedFile);
		assertEquals(expected, actual);
		// clean up...
		DeleteFileExtensions.delete(encryptedFile);
		DeleteFileExtensions.delete(decryptedFile);
	}

}
