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
package io.github.astrapi69.crypto.file;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertFalse;
import static org.testng.AssertJUnit.assertTrue;

import java.io.File;

import javax.crypto.Cipher;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import io.github.astrapi69.AbstractTestCase;
import io.github.astrapi69.checksum.FileChecksumExtensions;
import io.github.astrapi69.copy.CopyFileExtensions;
import io.github.astrapi69.crypto.algorithm.MdAlgorithm;
import io.github.astrapi69.crypto.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypto.model.CryptModel;
import io.github.astrapi69.crypto.model.StringDecorator;
import io.github.astrapi69.delete.DeleteFileExtensions;
import io.github.astrapi69.search.PathFinder;

public class PBEFileDecryptorTest extends AbstractTestCase<String, String>
{

	File cryptDir;
	CryptModel<Cipher, String, String> cryptModel;
	File decrypted;
	PBEFileDecryptor decryptor;
	File dirToEncrypt;
	File encrypted;
	PBEFileEncryptor encryptor;
	String password;
	File toEncrypt;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@Override
	@BeforeMethod
	protected void setUp()
	{
		cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		toEncrypt = new File(cryptDir, "test.txt");
		dirToEncrypt = new File(cryptDir, "food");
		password = "foo";
		cryptModel = CryptModel.<Cipher, String, String> builder().key(password)
			.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES)
			.decorator(StringDecorator.builder().prefix("$").suffix("?").build()).build();
	}

	/**
	 * Test method for the encrpytion with the class {@link PBEFileEncryptor} and decryption with
	 * the class {@link PBEFileDecryptor} with the constructor with model
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testDecryptWithModel() throws Exception
	{
		// new scenario...
		encryptor = new PBEFileEncryptor(cryptModel);
		encrypted = encryptor.encrypt(toEncrypt);

		decryptor = new PBEFileDecryptor(cryptModel);

		decrypted = decryptor.decrypt(encrypted);

		expected = FileChecksumExtensions.getChecksum(toEncrypt, MdAlgorithm.MD5.name());
		actual = FileChecksumExtensions.getChecksum(decrypted, MdAlgorithm.MD5.name());
		assertEquals(actual, expected);
		// clean up...
		DeleteFileExtensions.delete(encrypted);
		DeleteFileExtensions.delete(decrypted);
	}

	/**
	 * Test method for the encrpytion with the class {@link PBEFileEncryptor} and decryption with
	 * the class {@link PBEFileDecryptor} with the constructor with model and file
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testDecryptWithModelAndFile() throws Exception
	{
		// new scenario...
		File encryptedCnstr = new File(cryptDir, "encryptedCnstr.enc");
		File decryptedCnstr = new File(cryptDir, "decryptedCnstr.decrypted");
		encryptor = new PBEFileEncryptor(cryptModel, encryptedCnstr);
		encrypted = encryptor.encrypt(toEncrypt);

		decryptor = new PBEFileDecryptor(cryptModel, decryptedCnstr);

		decrypted = decryptor.decrypt(encrypted);

		expected = FileChecksumExtensions.getChecksum(toEncrypt, MdAlgorithm.MD5.name());
		actual = FileChecksumExtensions.getChecksum(decrypted, MdAlgorithm.MD5.name());
		assertEquals(actual, expected);
		// clean up...
		DeleteFileExtensions.delete(encrypted);
		DeleteFileExtensions.delete(decrypted);
	}

	/**
	 * Test method for the encrpytion with the class {@link PBEFileEncryptor} and decryption with
	 * the class {@link PBEFileDecryptor} with the constructor with model, file and custom file
	 * extension
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testDecryptWithModelAndFileAndWithCustomFileExtension() throws Exception
	{
		// new scenario...
		String customEncryptedFileExtension;
		String customDecryptedFileExtension;

		customEncryptedFileExtension = ".encfoo";
		customDecryptedFileExtension = ".decryptfoo";
		File encryptedCnstr = new File(cryptDir, "encryptedCnstr" + customEncryptedFileExtension);
		File decryptedCnstr = new File(cryptDir, "decryptedCnstr" + customDecryptedFileExtension);
		encryptor = new PBEFileEncryptor(cryptModel, encryptedCnstr, customEncryptedFileExtension);
		encrypted = encryptor.encrypt(toEncrypt);

		decryptor = new PBEFileDecryptor(cryptModel, decryptedCnstr, customDecryptedFileExtension);

		decrypted = decryptor.decrypt(encrypted);

		expected = FileChecksumExtensions.getChecksum(toEncrypt, MdAlgorithm.MD5.name());
		actual = FileChecksumExtensions.getChecksum(decrypted, MdAlgorithm.MD5.name());
		assertEquals(actual, expected);
		// clean up...
		DeleteFileExtensions.delete(encrypted);
		DeleteFileExtensions.delete(decrypted);
	}

	/**
	 * Test method for the encrpytion with the class {@link PBEFileEncryptor} and decryption with
	 * the class {@link PBEFileDecryptor} with the constructor with model, file, custom file
	 * extension and the delete flag
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testDecryptWithModelAndFileAndWithCustomFileExtensionAndDeleteFlag()
		throws Exception
	{
		// new scenario...
		String customEncryptedFileExtension;
		String customDecryptedFileExtension;

		customEncryptedFileExtension = ".encfoo";
		customDecryptedFileExtension = ".decryptfoo";
		File encryptedCnstr = new File(cryptDir, "encryptedCnstr" + customEncryptedFileExtension);
		File decryptedCnstr = new File(cryptDir, "decryptedCnstr" + customDecryptedFileExtension);
		encryptor = new PBEFileEncryptor(cryptModel, encryptedCnstr, customEncryptedFileExtension,
			true);
		File copyOfToEncrypt = new File(toEncrypt.getParent(), "copyOfToEncrypt.txt");
		boolean copyFileSuccessful = CopyFileExtensions.copyFile(toEncrypt, copyOfToEncrypt);
		assertTrue(copyFileSuccessful);
		encrypted = encryptor.encrypt(copyOfToEncrypt);
		assertFalse(copyOfToEncrypt.exists());

		decryptor = new PBEFileDecryptor(cryptModel, decryptedCnstr, customDecryptedFileExtension,
			true);

		File copyOfToEncrypted = new File(toEncrypt.getParent(),
			"copyOfEncryptedCnstr" + customEncryptedFileExtension);
		copyFileSuccessful = CopyFileExtensions.copyFile(toEncrypt, copyOfToEncrypted);
		assertTrue(copyFileSuccessful);
		decrypted = decryptor.decrypt(copyOfToEncrypted);
		assertFalse(copyOfToEncrypted.exists());
		// clean up...
		DeleteFileExtensions.delete(encrypted);
		DeleteFileExtensions.delete(decrypted);
	}
}
