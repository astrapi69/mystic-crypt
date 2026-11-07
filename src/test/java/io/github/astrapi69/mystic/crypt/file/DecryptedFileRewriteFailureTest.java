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
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.AbstractList;
import java.util.List;

import javax.crypto.Cipher;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import io.github.astrapi69.crypt.api.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.crypt.data.model.CryptObjectDecorator;

/**
 * The unit test class for a failed rewrite of the decrypted file in {@link FileDecryptor} and
 * {@link PBEFileDecryptor} (#272). With decorators, {@code onAfterDecrypt} reads the decrypted
 * file, strips the decorators and writes the file again. These tests let that write fail the way a
 * full disk makes it fail: the decrypted file is a symbolic link to a regular file while the
 * decryptor writes and reads it, and the decorator list re-points the link to {@code /dev/full},
 * where every write fails with "No space left on device", when the decryptor asks it for the
 * decorator, which is after the read and before the write.
 */
@EnabledOnOs(OS.LINUX)
public class DecryptedFileRewriteFailureTest
{

	private static final String KEY = "D1D15ED36B887AF1";

	/** a fixed salt so that separately built encryptor and decryptor models derive the same key */
	private static final byte[] SALT = { 1, 2, 3, 4, 5, 6, 7, 8 };

	private static final String CONTENT = "the quick brown fox jumps over the lazy dog";

	private static final Path DEV_FULL = Path.of("/dev/full");

	private static CryptObjectDecorator<String> newDecorator()
	{
		return CryptObjectDecorator.<String> builder().prefix("<<").suffix(">>").build();
	}

	private static CryptModel<Cipher, String, String> newCryptModel()
	{
		return CryptModel.<Cipher, String, String> builder().key(KEY)
			.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).salt(SALT).build();
	}

	private static CryptModel<Cipher, String, String> newEncryptionModel()
	{
		CryptModel<Cipher, String, String> model = newCryptModel();
		model.setDecorators(List.of(newDecorator()));
		return model;
	}

	/**
	 * The model of a decryptor whose decorator list re-points the given link to /dev/full when the
	 * decryptor asks it for its decorator. The list is set after the build, because the builder
	 * copies a list and would ask for the decorator while copying it.
	 */
	private static CryptModel<Cipher, String, String> newDecryptionModelThatFailsTheRewrite(
		final Path decryptedLink)
	{
		CryptModel<Cipher, String, String> model = newCryptModel();
		CryptObjectDecorator<String> decorator = newDecorator();
		model.setDecorators(new AbstractList<>()
		{
			@Override
			public CryptObjectDecorator<String> get(final int index)
			{
				repoint(decryptedLink, DEV_FULL);
				return decorator;
			}

			@Override
			public int size()
			{
				return 1;
			}
		});
		return model;
	}

	private static void repoint(final Path link, final Path target)
	{
		try
		{
			Files.delete(link);
			Files.createSymbolicLink(link, target);
		}
		catch (IOException exception)
		{
			throw new UncheckedIOException(exception);
		}
	}

	private static File newFileToEncrypt(final Path directory) throws IOException
	{
		return Files
			.writeString(directory.resolve("secret-message.txt"), CONTENT, StandardCharsets.UTF_8)
			.toFile();
	}

	private static File newEncryptedFile(final Path directory)
	{
		return directory.resolve("secret-message.enc").toFile();
	}

	/** A link that the decryptor writes the decrypted bytes through, to a regular file. */
	private static Path newDecryptedLink(final Path directory) throws IOException
	{
		Path regularFile = Files.createFile(directory.resolve("decrypted-target.txt"));
		return Files.createSymbolicLink(directory.resolve("decrypted.txt"), regularFile);
	}

	/**
	 * A {@link PBEFileDecryptor} that deletes the encrypted file after the decryption fails with
	 * the {@link IOException} of the failed rewrite, and keeps the encrypted original as it was.
	 *
	 * @param temporaryDirectory
	 *            the temporary directory of this test
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void pbeFileDecryptor_aFailedRewrite_failsTheDecryption_andKeepsTheEncryptedOriginal(
		@TempDir Path temporaryDirectory) throws Exception
	{
		File encrypted = new PBEFileEncryptor(newEncryptionModel(),
			newEncryptedFile(temporaryDirectory)).encrypt(newFileToEncrypt(temporaryDirectory));
		byte[] encryptedBytes = Files.readAllBytes(encrypted.toPath());
		Path decryptedLink = newDecryptedLink(temporaryDirectory);
		PBEFileDecryptor decryptor = new PBEFileDecryptor(
			newDecryptionModelThatFailsTheRewrite(decryptedLink), decryptedLink.toFile(),
			PBEFileDecryptor.DEFAULT_DECRYPTED_FILE_EXTENSION, true);

		assertThrows(IOException.class, () -> decryptor.decrypt(encrypted));

		assertEquals(DEV_FULL, Files.readSymbolicLink(decryptedLink),
			"the rewrite went to /dev/full");
		assertArrayEquals(encryptedBytes, Files.readAllBytes(encrypted.toPath()),
			"the encrypted original is kept as it was");
	}

	/**
	 * A {@link FileDecryptor} fails with the {@link IOException} of the failed rewrite.
	 *
	 * @param temporaryDirectory
	 *            the temporary directory of this test
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void fileDecryptor_aFailedRewrite_failsTheDecryption(@TempDir Path temporaryDirectory)
		throws Exception
	{
		File encrypted = new FileEncryptor(newEncryptionModel(),
			newEncryptedFile(temporaryDirectory)).encrypt(newFileToEncrypt(temporaryDirectory));
		Path decryptedLink = newDecryptedLink(temporaryDirectory);
		FileDecryptor decryptor = new FileDecryptor(
			newDecryptionModelThatFailsTheRewrite(decryptedLink), decryptedLink.toFile());

		assertThrows(IOException.class, () -> decryptor.decrypt(encrypted));

		assertEquals(DEV_FULL, Files.readSymbolicLink(decryptedLink),
			"the rewrite went to /dev/full");
	}
}
