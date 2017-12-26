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
package de.alpharogroup.crypto.file;

import java.io.File;

import javax.crypto.Cipher;

import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.SunJCEAlgorithm;
import de.alpharogroup.crypto.model.CryptModel;
import de.alpharogroup.file.delete.DeleteFileExtensions;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link FileEncryptor} and the class {@link FileDecryptor}.
 */
public class FileEncryptDecryptorTest
{

	/**
	 * Test method for the encrpytion with the class {@link FileEncryptor} and decryption with the
	 * class {@link FileDecryptor} with given constructor files.
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testEncryptDecryptConstructorFiles() throws Exception
	{
		final File cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		final File toEncrypt = new File(cryptDir, "test.txt");

		final String firstKey = "D1D15ED36B887AF1";

		final CryptModel<Cipher, String> cryptModel = CryptModel.<Cipher, String> builder()
			.key(firstKey).algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).build();

		final FileEncryptor encryptor = new FileEncryptor(cryptModel,
			new File(cryptDir, "encryptedCnstr.enc"));
		final File encrypted = encryptor.encrypt(toEncrypt);

		final FileDecryptor decryptor = new FileDecryptor(cryptModel,
			new File(cryptDir, "decryptedCnstr.decrypted"));

		final File decrypted = decryptor.decrypt(encrypted);
		// clean up...
		DeleteFileExtensions.delete(encrypted);
		DeleteFileExtensions.delete(decrypted);
	}

	/**
	 * Test method for the encrpytion with the class {@link FileEncryptor} and decryption with the
	 * class {@link FileDecryptor} with the default file name convention.
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testEncryptDecryptDefaultFiles() throws Exception
	{
		final File cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		final File toEncrypt = new File(cryptDir, "test.txt");

		final String firstKey = "D1D15ED36B887AF1";

		final CryptModel<Cipher, String> cryptModel = CryptModel.<Cipher, String> builder()
			.key(firstKey).algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).build();

		final FileEncryptor encryptor = new FileEncryptor(cryptModel);
		final File encrypted = encryptor.encrypt(toEncrypt);

		final FileDecryptor decryptor = new FileDecryptor(cryptModel);

		final File decrypted = decryptor.decrypt(encrypted);
		// clean up...
		DeleteFileExtensions.delete(encrypted);
		DeleteFileExtensions.delete(decrypted);
	}

	/**
	 * Test method for the encrpytion with the class {@link FileEncryptor} and decryption with the
	 * class {@link FileDecryptor} with factory injection.
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testEncryptDecryptFactoryInjected() throws Exception
	{
		final File cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		final File toEncrypt = new File(cryptDir, "test.txt");

		final String firstKey = "D1D15ED36B887AF1";

		final CryptModel<Cipher, String> cryptModel = CryptModel.<Cipher, String> builder()
			.key(firstKey).algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).build();

		final FileEncryptor encryptor = new FileEncryptor(cryptModel)
		{

			/** The Constant serialVersionUID. */
			private static final long serialVersionUID = 1L;

			@Override
			protected File newEncryptedFile(final String parent, final String child)
			{
				return new File(cryptDir, "encryptedFctrNjctd.enc");
			}
		};
		final File encrypted = encryptor.encrypt(toEncrypt);

		final FileDecryptor decryptor = new FileDecryptor(cryptModel)
		{

			/** The Constant serialVersionUID. */
			private static final long serialVersionUID = 1L;

			@Override
			protected File newDecryptedFile(final String parent, final String child)
			{
				return new File(cryptDir, "decryptedFctrNjctd.decrypted");
			}
		};

		final File decrypted = decryptor.decrypt(encrypted);
		// clean up...
		DeleteFileExtensions.delete(encrypted);
		DeleteFileExtensions.delete(decrypted);
	}

}
