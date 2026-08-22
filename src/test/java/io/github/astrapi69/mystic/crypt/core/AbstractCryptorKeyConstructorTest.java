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
package io.github.astrapi69.mystic.crypt.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.data.factory.CipherFactory;

/**
 * The unit test class for the key only constructors of the abstract cryptor classes
 * {@link AbstractFileEncryptor}, {@link AbstractFileDecryptor} and {@link AbstractObjectDecryptor}
 */
public class AbstractCryptorKeyConstructorTest
{

	private static final String PRIVATE_KEY = "top-secret-key";

	/**
	 * Test method for {@link AbstractFileEncryptor#AbstractFileEncryptor(String)}, the key only
	 * constructor has to create an initialized model with the given key
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void abstractFileEncryptor_withKeyOnly_createsAnInitializedModel() throws Exception
	{
		TestFileEncryptor encryptor = new TestFileEncryptor(PRIVATE_KEY);

		assertEquals(PRIVATE_KEY, encryptor.getModel().getKey());
		assertTrue(encryptor.getModel().isInitialized());
		assertNotNull(encryptor.getModel().getCipher());
		assertEquals(Cipher.ENCRYPT_MODE, encryptor.newOperationMode());
	}

	/**
	 * Test method for {@link AbstractFileDecryptor#AbstractFileDecryptor(String)}, the key only
	 * constructor has to create an initialized model with the given key
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void abstractFileDecryptor_withKeyOnly_createsAnInitializedModel() throws Exception
	{
		TestFileDecryptor decryptor = new TestFileDecryptor(PRIVATE_KEY);

		assertEquals(PRIVATE_KEY, decryptor.getModel().getKey());
		assertTrue(decryptor.getModel().isInitialized());
		assertNotNull(decryptor.getModel().getCipher());
		assertEquals(Cipher.DECRYPT_MODE, decryptor.newOperationMode());
	}

	/**
	 * Test method for {@link AbstractObjectDecryptor#AbstractObjectDecryptor(String)}, the key only
	 * constructor has to create an initialized model with the given key
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void abstractObjectDecryptor_withKeyOnly_createsAnInitializedModel() throws Exception
	{
		TestObjectDecryptor decryptor = new TestObjectDecryptor(PRIVATE_KEY);

		assertEquals(PRIVATE_KEY, decryptor.getModel().getKey());
		assertTrue(decryptor.getModel().isInitialized());
		assertNotNull(decryptor.getModel().getCipher());
		assertEquals(Cipher.DECRYPT_MODE, decryptor.newOperationMode());
	}

	private static Cipher newPbeCipher(final String key, final String algorithm, final byte[] salt,
		final int iterationCount, final int operationMode)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException
	{
		return CipherFactory.newPBECipher(key.toCharArray(), operationMode, algorithm, salt,
			iterationCount);
	}

	private static class TestFileEncryptor extends AbstractFileEncryptor
	{
		private static final long serialVersionUID = 1L;

		TestFileEncryptor(final String privateKey)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
		{
			super(privateKey);
		}

		@Override
		public File encrypt(final File toEncrypt)
		{
			throw new UnsupportedOperationException("not needed for this test");
		}

		@Override
		public byte[] encrypt(final byte[] toEncrypt)
		{
			throw new UnsupportedOperationException("not needed for this test");
		}

		@Override
		protected Cipher newCipher(final String key, final String algorithm, final byte[] salt,
			final int iterationCount, final int operationMode)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException
		{
			return newPbeCipher(key, algorithm, salt, iterationCount, operationMode);
		}
	}

	private static class TestFileDecryptor extends AbstractFileDecryptor
	{
		private static final long serialVersionUID = 1L;

		TestFileDecryptor(final String privateKey)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
		{
			super(privateKey);
		}

		@Override
		public File decrypt(final File encrypted)
		{
			throw new UnsupportedOperationException("not needed for this test");
		}

		@Override
		protected Cipher newCipher(final String key, final String algorithm, final byte[] salt,
			final int iterationCount, final int operationMode)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException
		{
			return newPbeCipher(key, algorithm, salt, iterationCount, operationMode);
		}
	}

	private static class TestObjectDecryptor extends AbstractObjectDecryptor<String, String>
	{
		private static final long serialVersionUID = 1L;

		TestObjectDecryptor(final String privateKey)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
		{
			super(privateKey);
		}

		@Override
		public String decrypt(final File encrypted)
		{
			throw new UnsupportedOperationException("not needed for this test");
		}

		@Override
		protected Cipher newCipher(final String key, final String algorithm, final byte[] salt,
			final int iterationCount, final int operationMode)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException
		{
			return newPbeCipher(key, algorithm, salt, iterationCount, operationMode);
		}
	}
}
