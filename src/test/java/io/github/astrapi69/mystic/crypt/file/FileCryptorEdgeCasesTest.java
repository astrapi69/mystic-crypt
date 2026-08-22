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
package io.github.astrapi69.mystic.crypt.file;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.util.List;

import javax.crypto.Cipher;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.astrapi69.collection.list.ListFactory;
import io.github.astrapi69.crypt.api.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.crypt.data.model.CryptObjectDecorator;
import io.github.astrapi69.file.read.ReadFileExtensions;
import io.github.astrapi69.file.write.StoreFileExtensions;

/**
 * The unit test class for the edge cases of the file based cryptors {@link FileEncryptor},
 * {@link FileDecryptor}, {@link PBEFileEncryptor}, {@link PBEFileDecryptor} and
 * {@link GenericObjectEncryptor}
 */
public class FileCryptorEdgeCasesTest
{

	private static final String KEY = "D1D15ED36B887AF1";

	/** a fixed salt so that separately built encryptor and decryptor models derive the same key */
	private static final byte[] SALT = { 1, 2, 3, 4, 5, 6, 7, 8 };

	private static final String CONTENT = "the quick brown fox jumps over the lazy dog";

	private static CryptModel<Cipher, String, String> newCryptModel(
		final List<CryptObjectDecorator<String>> decorators)
	{
		var builder = CryptModel.<Cipher, String, String> builder().key(KEY)
			.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).salt(SALT);
		if (decorators != null)
		{
			builder.decorators(decorators);
		}
		return builder.build();
	}

	private static List<CryptObjectDecorator<String>> newDecorators()
	{
		return ListFactory.newArrayList(
			CryptObjectDecorator.<String> builder().prefix("<<").suffix(">>").build());
	}

	private static File newFileToEncrypt(final File parent) throws Exception
	{
		File toEncrypt = new File(parent, "secret-message.txt");
		StoreFileExtensions.toFile(toEncrypt, CONTENT);
		return toEncrypt;
	}

	/**
	 * Test method for {@link FileEncryptor#encrypt(byte[])}, a file encryptor can not encrypt a
	 * byte array
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void fileEncryptor_canNotEncryptAByteArray() throws Exception
	{
		FileEncryptor encryptor = new FileEncryptor(newCryptModel(null));

		assertThrows(UnsupportedOperationException.class,
			() -> encryptor.encrypt(new byte[] { 1, 2, 3 }));
	}

	/**
	 * Test method for {@link PBEFileEncryptor#encrypt(byte[])}, a file encryptor can not encrypt a
	 * byte array
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void pbeFileEncryptor_canNotEncryptAByteArray() throws Exception
	{
		PBEFileEncryptor encryptor = new PBEFileEncryptor(newCryptModel(null));

		assertThrows(UnsupportedOperationException.class,
			() -> encryptor.encrypt(new byte[] { 1, 2, 3 }));
	}

	/**
	 * Test method for {@link GenericObjectEncryptor#encrypt(byte[])} and
	 * {@link GenericObjectEncryptor#newEncryptedFile(String, String)}
	 *
	 * @param temporaryDirectory
	 *            the temporary directory of this test
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void genericObjectEncryptor_byteArrayEncryptionIsEmptyAndNewEncryptedFileIsResolved(
		@TempDir File temporaryDirectory) throws Exception
	{
		GenericObjectEncryptor<String, String> encryptor = new GenericObjectEncryptor<>(
			newCryptModel(null), new File(temporaryDirectory, "encrypted.enc"));

		assertArrayEquals(new byte[0], encryptor.encrypt(new byte[] { 1, 2, 3 }));

		File newEncryptedFile = encryptor.newEncryptedFile(temporaryDirectory.getAbsolutePath(),
			"other.enc");
		assertEquals("other.enc", newEncryptedFile.getName());
		assertEquals(temporaryDirectory.getAbsolutePath(),
			newEncryptedFile.getParentFile().getAbsolutePath());
	}

	/**
	 * Test method for {@link FileEncryptor#encrypt(File)} and {@link FileDecryptor#decrypt(File)},
	 * a configured decorator must not break the round trip of the file content
	 *
	 * @param temporaryDirectory
	 *            the temporary directory of this test
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void fileEncryptorAndDecryptor_withDecorators_roundTripTheFileContent(
		@TempDir File temporaryDirectory) throws Exception
	{
		File toEncrypt = newFileToEncrypt(temporaryDirectory);
		File encryptedFile = new File(temporaryDirectory, "encrypted.enc");
		File decryptedFile = new File(temporaryDirectory, "decrypted.txt");

		FileEncryptor encryptor = new FileEncryptor(newCryptModel(newDecorators()), encryptedFile);
		FileDecryptor decryptor = new FileDecryptor(newCryptModel(newDecorators()), decryptedFile);

		File encrypted = encryptor.encrypt(toEncrypt);
		File decrypted = decryptor.decrypt(encrypted);

		assertEquals(CONTENT, ReadFileExtensions.fromFile(decrypted));
	}

	/**
	 * Test method for the file cryptors with an empty decorator list, the empty list must be
	 * treated like no decorators at all
	 *
	 * @param temporaryDirectory
	 *            the temporary directory of this test
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void fileCryptors_withAnEmptyDecoratorList_roundTripTheFileContent(
		@TempDir File temporaryDirectory) throws Exception
	{
		File toEncrypt = newFileToEncrypt(temporaryDirectory);
		List<CryptObjectDecorator<String>> noDecorators = ListFactory.newArrayList();

		File encrypted = new FileEncryptor(newCryptModel(noDecorators),
			new File(temporaryDirectory, "plain.enc")).encrypt(toEncrypt);
		File decrypted = new FileDecryptor(newCryptModel(noDecorators),
			new File(temporaryDirectory, "plain.txt")).decrypt(encrypted);
		File pbeEncrypted = new PBEFileEncryptor(newCryptModel(noDecorators),
			new File(temporaryDirectory, "pbe.enc")).encrypt(toEncrypt);
		File pbeDecrypted = new PBEFileDecryptor(newCryptModel(noDecorators),
			new File(temporaryDirectory, "pbe.txt")).decrypt(pbeEncrypted);

		assertEquals(CONTENT, ReadFileExtensions.fromFile(decrypted));
		assertEquals(CONTENT, ReadFileExtensions.fromFile(pbeDecrypted));
	}

	/**
	 * Test method for the file cryptors with the decorators explicitly set to null, which must be
	 * treated like no decorators at all
	 *
	 * @param temporaryDirectory
	 *            the temporary directory of this test
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void fileCryptors_withNullDecorators_roundTripTheFileContent(
		@TempDir File temporaryDirectory) throws Exception
	{
		File toEncrypt = newFileToEncrypt(temporaryDirectory);
		CryptModel<Cipher, String, String> model = newCryptModel(null);
		model.setDecorators(null);

		File encrypted = new FileEncryptor(model, new File(temporaryDirectory, "plain.enc"))
			.encrypt(toEncrypt);
		File decrypted = new FileDecryptor(model, new File(temporaryDirectory, "plain.txt"))
			.decrypt(encrypted);
		File pbeEncrypted = new PBEFileEncryptor(model, new File(temporaryDirectory, "pbe.enc"))
			.encrypt(toEncrypt);
		File pbeDecrypted = new PBEFileDecryptor(model, new File(temporaryDirectory, "pbe.txt"))
			.decrypt(pbeEncrypted);

		assertEquals(CONTENT, ReadFileExtensions.fromFile(decrypted));
		assertEquals(CONTENT, ReadFileExtensions.fromFile(pbeDecrypted));
	}

	/**
	 * Test method for {@link PBEFileEncryptor#encrypt(File)} and
	 * {@link PBEFileDecryptor#decrypt(File)}, a configured decorator must not break the round trip
	 * of the file content
	 *
	 * @param temporaryDirectory
	 *            the temporary directory of this test
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void pbeFileEncryptorAndDecryptor_withDecorators_roundTripTheFileContent(
		@TempDir File temporaryDirectory) throws Exception
	{
		File toEncrypt = newFileToEncrypt(temporaryDirectory);
		File encryptedFile = new File(temporaryDirectory, "encrypted.enc");
		File decryptedFile = new File(temporaryDirectory, "decrypted.txt");

		PBEFileEncryptor encryptor = new PBEFileEncryptor(newCryptModel(newDecorators()),
			encryptedFile);
		PBEFileDecryptor decryptor = new PBEFileDecryptor(newCryptModel(newDecorators()),
			decryptedFile);

		File encrypted = encryptor.encrypt(toEncrypt);
		File decrypted = decryptor.decrypt(encrypted);

		assertEquals(CONTENT, ReadFileExtensions.fromFile(decrypted));
	}
}
