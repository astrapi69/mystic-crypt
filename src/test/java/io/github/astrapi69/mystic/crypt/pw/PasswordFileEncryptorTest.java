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
package io.github.astrapi69.mystic.crypt.pw;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.util.Arrays;

import javax.crypto.Cipher;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.google.common.io.Files;

import io.github.astrapi69.checksum.FileChecksumExtensions;
import io.github.astrapi69.crypt.api.algorithm.MdAlgorithm;
import io.github.astrapi69.file.delete.DeleteFileExtensions;
import io.github.astrapi69.file.read.ReadFileExtensions;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.file.write.StoreFileExtensions;
import io.github.astrapi69.random.object.RandomStringFactory;

/**
 * The unit test class for the class {@link PasswordFileEncryptor}
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class PasswordFileEncryptorTest
{

	File cryptDir;
	File encrypted;
	PasswordFileEncryptor encryptor;
	String password;
	File toEncrypt;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeEach
	protected void setUp()
	{
		password = "foo";
		cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		toEncrypt = new File(cryptDir, "test.txt");
	}

	/**
	 * Test method for test the method {@link PasswordFileEncryptor#encrypt(File)}
	 *
	 * <p>
	 * A random salt is now generated per call, so the encrypted file content is no longer
	 * deterministic; assert round-trip correctness via checksum and non-determinism across two
	 * encryptions instead of a golden byte literal.
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testEncrypt() throws Exception
	{
		File firstEncrypted = new File(cryptDir, "encryptedCnstr.enc");
		File secondEncrypted = new File(cryptDir, "encryptedCnstrSecond.enc");
		new PasswordFileEncryptor(password, firstEncrypted).encrypt(toEncrypt);
		new PasswordFileEncryptor(password, secondEncrypted).encrypt(toEncrypt);

		assertFalse(
			Arrays.equals(Files.toByteArray(firstEncrypted), Files.toByteArray(secondEncrypted)));

		File decrypted = new File(cryptDir, "decryptedCnstr.decrypted");
		new PasswordFileDecryptor(password, decrypted).decrypt(firstEncrypted);
		assertEquals(FileChecksumExtensions.getChecksum(toEncrypt, MdAlgorithm.MD5.name()),
			FileChecksumExtensions.getChecksum(decrypted, MdAlgorithm.MD5.name()));

		// clean up...
		DeleteFileExtensions.delete(firstEncrypted);
		DeleteFileExtensions.delete(secondEncrypted);
		DeleteFileExtensions.delete(decrypted);
	}

	/**
	 * Test method for test the method {@link PasswordFileEncryptor#encrypt(File)}
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	@Disabled
	public void testEncryptBigFile() throws Exception
	{
		byte[] actual;
		byte[] expected;
		File encryptedCnstr;
		String encryptedFilename;
		String longString;
		// new scenario...
		encryptedFilename = "bigEncryptedFile.txt";
		longString = RandomStringFactory.newRandomLongString(10000000);
		encryptedCnstr = new File(cryptDir, encryptedFilename);
		StoreFileExtensions.toFile(encryptedCnstr, longString);
		encryptor = new PasswordFileEncryptor(password);
		encrypted = encryptor.encrypt(encryptedCnstr);
		// actual = Files.toByteArray(encryptedCnstr);
		// // clean up...
		DeleteFileExtensions.delete(encrypted);
		DeleteFileExtensions.delete(encryptedCnstr);
	}

	/**
	 * Test method for {@link PasswordFileEncryptor#encrypt(File)}, without an explicit encrypted
	 * file the base name of the source file with the extension '.enc' is used
	 *
	 * @param temporaryDirectory
	 *            the temporary directory of this test
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void encrypt_withoutAnExplicitEncryptedFile_derivesTheFileNameFromTheSourceFile(
		@TempDir File temporaryDirectory) throws Exception
	{
		File source = new File(temporaryDirectory, "secret-message.txt");
		StoreFileExtensions.toFile(source, "the quick brown fox jumps over the lazy dog");

		File encryptedFile = new PasswordFileEncryptor(password).encrypt(source);

		assertEquals("secret-message.enc", encryptedFile.getName());
		assertEquals(temporaryDirectory.getAbsolutePath(),
			encryptedFile.getParentFile().getAbsolutePath());

		File decryptedFile = new PasswordFileDecryptor(password,
			new File(temporaryDirectory, "decrypted.txt")).decrypt(encryptedFile);
		assertEquals("the quick brown fox jumps over the lazy dog",
			ReadFileExtensions.fromFile(decryptedFile));
	}

	/**
	 * Test method for {@link PasswordFileEncryptor#resetPassword()}, after the password is reset
	 * nothing can be encrypted anymore
	 *
	 * @param temporaryDirectory
	 *            the temporary directory of this test
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void resetPassword_clearsThePasswordSoNothingCanBeEncryptedAnymore(
		@TempDir File temporaryDirectory) throws Exception
	{
		File source = new File(temporaryDirectory, "secret-message.txt");
		StoreFileExtensions.toFile(source, "the quick brown fox");
		PasswordFileEncryptor encryptor = new PasswordFileEncryptor(password,
			new File(temporaryDirectory, "encrypted.enc"));

		encryptor.resetPassword();

		assertThrows(NullPointerException.class, () -> encryptor.encrypt(source));
	}

	/**
	 * Test method for {@link PasswordFileEncryptor#encrypt(File)}, the file to encrypt is mandatory
	 */
	@Test
	public void encrypt_withoutAFile_throwsANullPointerException()
	{
		PasswordFileEncryptor encryptor = new PasswordFileEncryptor(password);

		assertThrows(NullPointerException.class, () -> encryptor.encrypt(null));
	}

	/**
	 * Test method for {@link PasswordFileEncryptor#newOperationMode()}
	 */
	@Test
	public void newOperationMode_isTheEncryptMode()
	{
		assertEquals(Cipher.ENCRYPT_MODE, new PasswordFileEncryptor(password).newOperationMode());
	}
}
