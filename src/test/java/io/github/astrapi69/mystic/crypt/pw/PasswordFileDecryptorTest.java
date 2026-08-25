/*
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
package io.github.astrapi69.mystic.crypt.pw;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;

import javax.crypto.Cipher;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.astrapi69.checksum.FileChecksumExtensions;
import io.github.astrapi69.crypt.api.algorithm.MdAlgorithm;
import io.github.astrapi69.file.delete.DeleteFileExtensions;
import io.github.astrapi69.file.read.ReadFileExtensions;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.file.write.StoreFileExtensions;
import io.github.astrapi69.test.base.AbstractTestCase;

/**
 * The unit test class for the class {@link PasswordFileDecryptor}
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class PasswordFileDecryptorTest extends AbstractTestCase<String, String>
{

	File cryptDir;
	File decrypted;
	PasswordFileDecryptor decryptor;
	File encrypted;
	PasswordFileEncryptor encryptor;
	File toEncrypt;
	String password;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@Override
	@BeforeEach
	protected void setUp()
	{
		password = "foo";
		cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		toEncrypt = new File(cryptDir, "test.txt");
	}

	/**
	 * Test method for test the method {@link PasswordFileDecryptor#decrypt(File)}
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testDecrypt() throws Exception
	{

		File encryptedCnstr;
		File decryptedCnstr;
		String encryptedFilename;
		String decryptedFilename;
		// new scenario...
		encryptedFilename = "encryptedCnstr.enc";
		decryptedFilename = "decryptedCnstr.decrypted";
		encryptedCnstr = new File(cryptDir, encryptedFilename);
		decryptedCnstr = new File(cryptDir, decryptedFilename);
		encryptor = new PasswordFileEncryptor(password, encryptedCnstr);
		encrypted = encryptor.encrypt(toEncrypt);

		decryptor = new PasswordFileDecryptor(password, decryptedCnstr);

		decrypted = decryptor.decrypt(encrypted);

		expected = FileChecksumExtensions.getChecksum(toEncrypt, MdAlgorithm.MD5.name());
		actual = FileChecksumExtensions.getChecksum(decrypted, MdAlgorithm.MD5.name());
		assertEquals(actual, expected);
		// clean up...
		DeleteFileExtensions.delete(encrypted);
		DeleteFileExtensions.delete(decrypted);
	}

	/**
	 * Test method for {@link PasswordFileDecryptor#decrypt(File)}, without an explicit decrypted
	 * file the base name of the encrypted file with the extension '.decrypted' is used
	 *
	 * @param temporaryDirectory
	 *            the temporary directory of this test
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void decrypt_withoutAnExplicitDecryptedFile_derivesTheFileNameFromTheEncryptedFile(
		@TempDir File temporaryDirectory) throws Exception
	{
		File source = new File(temporaryDirectory, "secret-message.txt");
		StoreFileExtensions.toFile(source, "the quick brown fox jumps over the lazy dog");
		File encryptedFile = new PasswordFileEncryptor(password,
			new File(temporaryDirectory, "secret-message.enc")).encrypt(source);

		File decryptedFile = new PasswordFileDecryptor(password, null).decrypt(encryptedFile);

		assertEquals("secret-message.decrypted", decryptedFile.getName());
		assertEquals("the quick brown fox jumps over the lazy dog",
			ReadFileExtensions.fromFile(decryptedFile));
	}

	/**
	 * Test method for {@link PasswordFileDecryptor#decrypt(File)}, an encrypted file that is
	 * shorter than the salt prefix has to be rejected
	 *
	 * @param temporaryDirectory
	 *            the temporary directory of this test
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void decrypt_withAFileShorterThanTheSaltPrefix_throwsAnIllegalArgumentException(
		@TempDir File temporaryDirectory) throws Exception
	{
		File tooShort = new File(temporaryDirectory, "too-short.enc");
		StoreFileExtensions.toFile(tooShort, "abc");
		PasswordFileDecryptor fileDecryptor = new PasswordFileDecryptor(password,
			new File(temporaryDirectory, "decrypted.txt"));

		assertThrows(IllegalArgumentException.class, () -> fileDecryptor.decrypt(tooShort));
	}

	/**
	 * Test method for {@link PasswordFileDecryptor#resetPassword()}, after the password is reset
	 * nothing can be decrypted anymore
	 *
	 * @param temporaryDirectory
	 *            the temporary directory of this test
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void resetPassword_clearsThePasswordSoNothingCanBeDecryptedAnymore(
		@TempDir File temporaryDirectory) throws Exception
	{
		File source = new File(temporaryDirectory, "secret-message.txt");
		StoreFileExtensions.toFile(source, "the quick brown fox");
		File encryptedFile = new PasswordFileEncryptor(password,
			new File(temporaryDirectory, "secret-message.enc")).encrypt(source);
		PasswordFileDecryptor fileDecryptor = new PasswordFileDecryptor(password,
			new File(temporaryDirectory, "decrypted.txt"));

		fileDecryptor.resetPassword();

		assertThrows(NullPointerException.class, () -> fileDecryptor.decrypt(encryptedFile));
	}

	/**
	 * Test method for {@link PasswordFileDecryptor#decrypt(File)}, the encrypted file is mandatory
	 */
	@Test
	public void decrypt_withoutAFile_throwsANullPointerException()
	{
		PasswordFileDecryptor fileDecryptor = new PasswordFileDecryptor(password, null);

		assertThrows(NullPointerException.class, () -> fileDecryptor.decrypt(null));
	}

	/**
	 * Test method for {@link PasswordFileDecryptor#newOperationMode()}
	 */
	@Test
	public void newOperationMode_isTheDecryptMode()
	{
		assertEquals(Cipher.DECRYPT_MODE,
			new PasswordFileDecryptor(password, null).newOperationMode());
	}

	/**
	 * Test method for {@link PasswordFileDecryptor#decrypt(File)} with the wrong password: the
	 * plaintext must never come back. The cipher is unauthenticated CBC, so a wrong key usually
	 * fails the padding check but can (about 1 in 256) produce garbage instead of an exception -
	 * the assertion therefore accepts either, but never the original content.
	 *
	 * @param temporaryDirectory
	 *            the temporary directory of this test
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void decrypt_withTheWrongPassword_neverYieldsThePlaintext(
		@TempDir File temporaryDirectory) throws Exception
	{
		File source = new File(temporaryDirectory, "secret-message.txt");
		StoreFileExtensions.toFile(source, "the quick brown fox jumps over the lazy dog");
		File encryptedFile = new PasswordFileEncryptor(password,
			new File(temporaryDirectory, "secret-message.enc")).encrypt(source);
		PasswordFileDecryptor fileDecryptor = new PasswordFileDecryptor("wrong-password",
			new File(temporaryDirectory, "decrypted.txt"));

		try
		{
			File decryptedFile = fileDecryptor.decrypt(encryptedFile);
			assertNotEquals(FileChecksumExtensions.getChecksum(source, MdAlgorithm.MD5.name()),
				FileChecksumExtensions.getChecksum(decryptedFile, MdAlgorithm.MD5.name()),
				"decrypting with the wrong password must never yield the original content");
		}
		catch (Exception exception)
		{
			// expected: the wrong key fails inside the cipher
		}
	}
}
