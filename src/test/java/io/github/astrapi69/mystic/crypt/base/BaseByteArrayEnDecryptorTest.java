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
package io.github.astrapi69.mystic.crypt.base;

import static org.testng.AssertJUnit.assertEquals;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import io.github.astrapi69.mystic.crypt.base.BaseByteArrayDecryptor;
import io.github.astrapi69.mystic.crypt.base.BaseByteArrayEncryptor;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import io.github.astrapi69.crypt.api.algorithm.AesAlgorithm;
import io.github.astrapi69.crypt.data.factory.SecretKeyFactoryExtensions;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.random.object.RandomStringFactory;

public class BaseByteArrayEnDecryptorTest
{

	CryptModel<Cipher, SecretKey, String> cryptModel;
	SecretKey secretKey;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@BeforeMethod
	protected void setUp() throws Exception
	{
		secretKey = SecretKeyFactoryExtensions.newSecretKey(AesAlgorithm.AES.name(), 128);
		cryptModel = CryptModel.<Cipher, SecretKey, String> builder().key(secretKey)
			.algorithm(AesAlgorithm.AES).build();
	}

	/**
	 * Test method for {@link BaseByteArrayEncryptor#encrypt(byte[])}
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public void testDecrypt() throws Exception
	{
		// declare variables
		BaseByteArrayEncryptor encryptor;
		BaseByteArrayDecryptor decryptor;
		String plainMessage;
		plainMessage = RandomStringFactory.newRandomLongString(10000);

		encryptor = new BaseByteArrayEncryptor(cryptModel);
		decryptor = new BaseByteArrayDecryptor(cryptModel);
		byte[] plainMessageBytes = plainMessage.getBytes(StandardCharsets.UTF_8);
		byte[] encryptedBytes = encryptor.encrypt(plainMessageBytes);
		byte[] decrypt = decryptor.decrypt(encryptedBytes);
		String decryptedMessage = new String(decrypt, StandardCharsets.UTF_8);
		assertEquals(plainMessage, decryptedMessage);

	}

}
