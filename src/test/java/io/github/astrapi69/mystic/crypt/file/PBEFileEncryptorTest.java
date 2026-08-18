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
package io.github.astrapi69.mystic.crypt.file;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.io.File;
import java.nio.file.Files;

import javax.crypto.Cipher;

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

public class PBEFileEncryptorTest extends AbstractTestCase<String, String>
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

	@Test
	public void testEncrypt() throws Exception
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
	 * Regression test for a bug where
	 * {@link PBEFileEncryptor#newCipher(String, String, byte[], int, int)} silently discarded the
	 * salt/iterationCount it was given, always falling back to
	 * {@link io.github.astrapi69.crypt.api.algorithm.compound.CompoundAlgorithm}'s hardcoded
	 * defaults regardless of what was set on the {@link CryptModel}.
	 */
	@Test
	public void testEncryptWithDifferentExplicitSaltsProducesDifferentCiphertext() throws Exception
	{
		byte[] firstSalt = { 1, 2, 3, 4, 5, 6, 7, 8 };
		byte[] secondSalt = { 8, 7, 6, 5, 4, 3, 2, 1 };
		CryptModel<Cipher, String, String> firstModel = CryptModel
			.<Cipher, String, String> builder().key(password)
			.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).salt(firstSalt).build();
		CryptModel<Cipher, String, String> secondModel = CryptModel
			.<Cipher, String, String> builder().key(password)
			.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES).salt(secondSalt).build();

		File firstEncrypted = new File(cryptDir, "firstSalt.enc");
		File secondEncrypted = new File(cryptDir, "secondSalt.enc");
		new PBEFileEncryptor(firstModel, firstEncrypted).encrypt(toEncrypt);
		new PBEFileEncryptor(secondModel, secondEncrypted).encrypt(toEncrypt);

		byte[] firstBytes = Files.readAllBytes(firstEncrypted.toPath());
		byte[] secondBytes = Files.readAllBytes(secondEncrypted.toPath());
		assertFalse(java.util.Arrays.equals(firstBytes, secondBytes));

		// clean up...
		DeleteFileExtensions.delete(firstEncrypted);
		DeleteFileExtensions.delete(secondEncrypted);
	}
}
