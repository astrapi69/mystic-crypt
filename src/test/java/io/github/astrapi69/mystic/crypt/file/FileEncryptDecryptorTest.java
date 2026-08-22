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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import javax.crypto.Cipher;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.checksum.FileChecksumExtensions;
import io.github.astrapi69.crypt.api.algorithm.MdAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.crypt.data.model.CryptObjectDecorator;
import io.github.astrapi69.file.delete.DeleteFileExtensions;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.test.base.AbstractTestCase;

/**
 * The unit test class for the class {@link FileEncryptor} and the class {@link FileDecryptor}
 */
public class FileEncryptDecryptorTest extends AbstractTestCase<String, String>
{

	File cryptDir;
	CryptModel<Cipher, String, String> cryptModel;
	File decrypted;
	FileDecryptor decryptor;
	File dirToEncrypt;
	File encrypted;
	FileEncryptor encryptor;
	String firstKey;
	File toEncrypt;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@Override
	@BeforeEach
	protected void setUp()
	{
		cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		toEncrypt = new File(cryptDir, "test.txt");
		dirToEncrypt = new File(cryptDir, "food");
		firstKey = "D1D15ED36B887AF1";
		cryptModel = CryptModel.<Cipher, String, String> builder().key(firstKey)
			.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES)
			.decorator(CryptObjectDecorator.<String> builder().prefix("$").suffix("?").build())
			.build();
	}

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
		// new scenario...
		File encryptedCnstr = new File(cryptDir, "encryptedCnstr.enc");
		File decryptedCnstr = new File(cryptDir, "decryptedCnstr.decrypted");
		encryptor = new FileEncryptor(cryptModel, encryptedCnstr);
		encrypted = encryptor.encrypt(toEncrypt);

		decryptor = new FileDecryptor(cryptModel, decryptedCnstr);

		decrypted = decryptor.decrypt(encrypted);

		expected = FileChecksumExtensions.getChecksum(toEncrypt, MdAlgorithm.MD5.name());
		actual = FileChecksumExtensions.getChecksum(decrypted, MdAlgorithm.MD5.name());
		assertEquals(actual, expected);
		// clean up...
		DeleteFileExtensions.delete(encrypted);
		DeleteFileExtensions.delete(decrypted);
	}

	/**
	 * Test method for the encrpytion with the class {@link FileEncryptor} and decryption with the
	 * class {@link FileDecryptor} with given constructor files that throws a
	 * {@link FileNotFoundException}
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testEncryptDecryptConstructorFilesThrowFileNotFoundException() throws Exception
	{
		Assertions.assertThrows(FileNotFoundException.class, () -> {
			// new scenario...
			encryptor = new FileEncryptor(cryptModel, new File(cryptDir, "foodenc"));
			encrypted = encryptor.encrypt(dirToEncrypt);
		});
	}

	/**
	 * Test method for the encrpytion with the class {@link FileEncryptor} and decryption with the
	 * class {@link FileDecryptor} with the default file name convention
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testEncryptDecryptDefaultFiles() throws Exception
	{
		encryptor = new FileEncryptor(cryptModel);
		encrypted = encryptor.encrypt(toEncrypt);

		decryptor = new FileDecryptor(cryptModel);

		decrypted = decryptor.decrypt(encrypted);

		expected = FileChecksumExtensions.getChecksum(toEncrypt, MdAlgorithm.MD5.name());
		actual = FileChecksumExtensions.getChecksum(decrypted, MdAlgorithm.MD5.name());
		assertEquals(actual, expected);
		// clean up...
		DeleteFileExtensions.delete(encrypted);
		DeleteFileExtensions.delete(decrypted);
	}

	/**
	 * Test method for the encrpytion with the class {@link FileEncryptor} and decryption with the
	 * class {@link FileDecryptor} with factory injection
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testEncryptDecryptFactoryInjected() throws Exception
	{
		encryptor = new FileEncryptor(cryptModel)
		{

			/** The Constant serialVersionUID. */
			private static final long serialVersionUID = 1L;

			@Override
			protected File newEncryptedFile(final String parent, final String child)
			{
				return new File(cryptDir, "encryptedFctrNjctd.enc");
			}
		};
		encrypted = encryptor.encrypt(toEncrypt);

		decryptor = new FileDecryptor(cryptModel)
		{

			/** The Constant serialVersionUID. */
			private static final long serialVersionUID = 1L;

			@Override
			protected File newDecryptedFile(final String parent, final String child)
			{
				return new File(cryptDir, "decryptedFctrNjctd.decrypted");
			}
		};

		decrypted = decryptor.decrypt(encrypted);

		expected = FileChecksumExtensions.getChecksum(toEncrypt, MdAlgorithm.MD5.name());
		actual = FileChecksumExtensions.getChecksum(decrypted, MdAlgorithm.MD5.name());
		assertEquals(actual, expected);

		// clean up...
		DeleteFileExtensions.delete(encrypted);
		DeleteFileExtensions.delete(decrypted);
	}

	/**
	 * Test method for {@link FileDecryptor#decrypt(File)} that pins the observable effect of the
	 * {@code onAfterDecrypt} post-processing step: the encryptor wraps the content in the
	 * {@link CryptModel}'s decorator ("$" prefix, "?" suffix), and decryption with the same model
	 * strips it again, so the round trip recovers the plain input - while decrypting the same
	 * ciphertext with a model that has no decorator exposes the markers the encryptor added. (An
	 * earlier version of this test wrote the markers into the plain file by hand and expected them
	 * stripped; that only passed because the encryptor used to discard the decorated content, see
	 * FileDecoratorRoundTripTest.)
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void decrypt_appliesTheDecoratorUndecorationInOnAfterDecrypt() throws Exception
	{
		java.nio.file.Path tempDir = Files.createTempDirectory("file-marker");
		File plain = tempDir.resolve("plain.txt").toFile();
		Files.write(plain.toPath(), "hello".getBytes(StandardCharsets.UTF_8));
		File markerEncrypted = tempDir.resolve("marker.enc").toFile();
		File withDecorator = tempDir.resolve("with-decorator.decrypted").toFile();
		File withoutDecorator = tempDir.resolve("without-decorator.decrypted").toFile();
		// the model without the decorator must share key and salt with the decorated one,
		// otherwise it cannot decrypt at all
		byte[] salt = { 1, 2, 3, 4, 5, 6, 7, 8 };
		CryptModel<Cipher, String, String> decorated = CryptModel.<Cipher, String, String> builder()
			.key(firstKey).algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).salt(salt)
			.decorator(CryptObjectDecorator.<String> builder().prefix("$").suffix("?").build())
			.build();
		CryptModel<Cipher, String, String> undecorated = CryptModel
			.<Cipher, String, String> builder().key(firstKey)
			.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).salt(salt).build();

		encrypted = new FileEncryptor(decorated, markerEncrypted).encrypt(plain);

		String roundTrip = new String(
			Files.readAllBytes(
				new FileDecryptor(decorated, withDecorator).decrypt(encrypted).toPath()),
			StandardCharsets.UTF_8);
		String exposed = new String(
			Files.readAllBytes(
				new FileDecryptor(undecorated, withoutDecorator).decrypt(encrypted).toPath()),
			StandardCharsets.UTF_8);

		assertEquals("hello", roundTrip);
		assertEquals("$hello?", exposed);

		// clean up...
		DeleteFileExtensions.delete(tempDir.toFile());
	}

}
