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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.stream.Stream;

import javax.crypto.Cipher;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.checksum.FileChecksumExtensions;
import io.github.astrapi69.crypt.api.algorithm.MdAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.crypt.data.model.CryptObjectDecorator;
import io.github.astrapi69.file.copy.CopyFileExtensions;
import io.github.astrapi69.file.delete.DeleteFileExtensions;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.test.base.AbstractTestCase;

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
	@BeforeEach
	protected void setUp()
	{
		cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		toEncrypt = new File(cryptDir, "test.txt");
		dirToEncrypt = new File(cryptDir, "food");
		password = "foo";
		cryptModel = CryptModel.<Cipher, String, String> builder().key(password)
			.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES)
			.decorator(CryptObjectDecorator.<String> builder().prefix("$").suffix("?").build())
			.build();
	}

	/**
	 * One constructor-variant case: the encrypt-decrypt-checksum round trip is identical, only how
	 * encryptor and decryptor are constructed differs.
	 */
	record ConstructorCase(String description, PbeEncryptorFactory encryptorFactory,
		PbeDecryptorFactory decryptorFactory) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	/** Builds the encryptor of one constructor variant. */
	@FunctionalInterface
	interface PbeEncryptorFactory
	{
		PBEFileEncryptor create(CryptModel<Cipher, String, String> model, File directory)
			throws Exception;
	}

	/** Builds the decryptor of one constructor variant. */
	@FunctionalInterface
	interface PbeDecryptorFactory
	{
		PBEFileDecryptor create(CryptModel<Cipher, String, String> model, File directory)
			throws Exception;
	}

	static Stream<ConstructorCase> constructorCases()
	{
		return Stream.of(
			new ConstructorCase("model only", (model, directory) -> new PBEFileEncryptor(model),
				(model, directory) -> new PBEFileDecryptor(model)),
			new ConstructorCase("model and file",
				(model, directory) -> new PBEFileEncryptor(model,
					new File(directory, "encryptedCnstr.enc")),
				(model, directory) -> new PBEFileDecryptor(model,
					new File(directory, "decryptedCnstr.decrypted"))),
			new ConstructorCase("model, file and custom file extension",
				(model, directory) -> new PBEFileEncryptor(model,
					new File(directory, "encryptedCnstr.encfoo"), ".encfoo"),
				(model, directory) -> new PBEFileDecryptor(model,
					new File(directory, "decryptedCnstr.decryptfoo"), ".decryptfoo")));
	}

	/**
	 * Test method for the encryption with the class {@link PBEFileEncryptor} and decryption with
	 * the class {@link PBEFileDecryptor} over every constructor variant
	 *
	 * @param testCase
	 *            the constructor-variant case
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@ParameterizedTest
	@MethodSource("constructorCases")
	public void testEncryptDecryptRoundTrip(ConstructorCase testCase) throws Exception
	{
		encryptor = testCase.encryptorFactory().create(cryptModel, cryptDir);
		encrypted = encryptor.encrypt(toEncrypt);

		decryptor = testCase.decryptorFactory().create(cryptModel, cryptDir);

		decrypted = decryptor.decrypt(encrypted);

		expected = FileChecksumExtensions.getChecksum(toEncrypt, MdAlgorithm.MD5.name());
		actual = FileChecksumExtensions.getChecksum(decrypted, MdAlgorithm.MD5.name());
		assertEquals(actual, expected, testCase.description());
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
