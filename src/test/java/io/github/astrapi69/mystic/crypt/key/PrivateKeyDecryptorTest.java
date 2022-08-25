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
package io.github.astrapi69.mystic.crypt.key;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import io.github.astrapi69.mystic.crypt.key.PrivateKeyDecryptor;
import io.github.astrapi69.mystic.crypt.key.PublicKeyEncryptor;
import org.testng.annotations.Test;

import io.github.astrapi69.crypt.api.algorithm.AesAlgorithm;
import io.github.astrapi69.crypt.data.factory.SecretKeyFactoryExtensions;
import io.github.astrapi69.crypt.data.key.PrivateKeyExtensions;
import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.random.object.RandomStringFactory;

/**
 * The unit test class for the class {@link PrivateKeyDecryptor}
 */
public class PrivateKeyDecryptorTest
{

	/**
	 * Test method for {@link PrivateKeyDecryptor} constructor with {@link PrivateKey} object
	 *
	 * @throws Exception
	 *             is thrown if instantiation of the cipher object fails.
	 */
	@Test
	public void testConstructorWithPrivateKey() throws Exception
	{

		String actual;
		String expected;
		PrivateKey privateKey;
		PublicKey publicKey;
		byte[] testBytes;
		File derDir;
		File privatekeyDerFile;
		PublicKeyEncryptor encryptor;
		PrivateKeyDecryptor decryptor;
		byte[] decrypted;

		actual = RandomStringFactory.newRandomLongString(10000000);

		testBytes = actual.getBytes("UTF-8");

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privatekeyDerFile = new File(derDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);
		publicKey = PrivateKeyExtensions.generatePublicKey(privateKey);

		encryptor = new PublicKeyEncryptor(publicKey);
		assertNotNull(encryptor);

		byte[] encrypt = encryptor.encrypt(testBytes);

		decryptor = new PrivateKeyDecryptor(privateKey);
		assertNotNull(decryptor);
		decrypted = decryptor.decrypt(encrypt);
		assertNotNull(decrypted);
		expected = new String(decrypted, "UTF-8");
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link PrivateKeyDecryptor} constructor with {@link CryptModel} object
	 *
	 * @throws Exception
	 *             is thrown if instantiation of the cipher object fails.
	 */
	@Test
	public void testConstructorWithCryptModel() throws Exception
	{
		String actual;
		String expected;
		PrivateKey privateKey;
		PublicKey publicKey;
		SecretKey symmetricKey;
		CryptModel<Cipher, PublicKey, byte[]> encryptModel;
		CryptModel<Cipher, SecretKey, String> symmetricKeyModel;
		CryptModel<Cipher, PrivateKey, byte[]> decryptModel;
		byte[] testBytes;
		File derDir;
		File privatekeyDerFile;
		PublicKeyEncryptor encryptor;
		PrivateKeyDecryptor decryptor;
		byte[] decrypted;

		actual = RandomStringFactory.newRandomLongString(10000000);

		testBytes = actual.getBytes("UTF-8");

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privatekeyDerFile = new File(derDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);
		publicKey = PrivateKeyExtensions.generatePublicKey(privateKey);

		decryptModel = CryptModel.<Cipher, PrivateKey, byte[]> builder().key(privateKey).build();
		encryptModel = CryptModel.<Cipher, PublicKey, byte[]> builder().key(publicKey).build();
		symmetricKey = SecretKeyFactoryExtensions.newSecretKey(AesAlgorithm.AES.getAlgorithm(),
			128);
		symmetricKeyModel = CryptModel.<Cipher, SecretKey, String> builder().key(symmetricKey)
			.algorithm(AesAlgorithm.AES).operationMode(Cipher.ENCRYPT_MODE).build();

		encryptor = new PublicKeyEncryptor(encryptModel, symmetricKeyModel);
		assertNotNull(encryptor);

		byte[] encrypt = encryptor.encrypt(testBytes);

		decryptor = new PrivateKeyDecryptor(decryptModel);
		assertNotNull(decryptor);
		decrypted = decryptor.decrypt(encrypt);
		assertNotNull(decrypted);
		expected = new String(decrypted, "UTF-8");
		assertEquals(expected, actual);
	}
}
