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
package io.github.astrapi69.mystic.crypt.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.api.algorithm.compound.CompoundAlgorithm;

/**
 * The unit test class for the {@link javax.crypto.SecretKey} constructor of
 * {@link AbstractByteArrayDecryptor}. Its only in-repo subclass, {@code BaseByteArrayDecryptor},
 * routes its key-only constructor through {@code this(newModel(symmetricKey))} and therefore never
 * reaches {@link AbstractByteArrayDecryptor#AbstractByteArrayDecryptor(SecretKey)}. This test
 * exercises that constructor directly through a minimal subclass.
 */
public class AbstractByteArrayDecryptorTest
{

	/**
	 * Test method for {@link AbstractByteArrayDecryptor#AbstractByteArrayDecryptor(SecretKey)}, the
	 * symmetric-key constructor delegates to the default model, whose transformation is the PBE
	 * transformation, so a PBE key is used and the constructed decryptor must carry an initialized
	 * model with the given key
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void abstractByteArrayDecryptor_withSymmetricKeyOnly_createsAnInitializedModel()
		throws Exception
	{
		final String algorithm = CompoundAlgorithm.PBE_WITH_SHA1_AND_128BIT_AES_CBC_BC
			.getAlgorithm();
		final SecretKey pbeKey = SecretKeyFactory.getInstance(algorithm, "BC")
			.generateSecret(new PBEKeySpec("top secret".toCharArray(),
				new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, 1000));

		final TestByteArrayDecryptor decryptor = new TestByteArrayDecryptor(pbeKey);

		assertEquals(pbeKey, decryptor.getModel().getKey());
		assertTrue(decryptor.getModel().isInitialized());
		assertNotNull(decryptor.getModel().getCipher());
		assertEquals(Cipher.DECRYPT_MODE, decryptor.newOperationMode());
	}

	private static class TestByteArrayDecryptor extends AbstractByteArrayDecryptor
	{
		private static final long serialVersionUID = 1L;

		TestByteArrayDecryptor(final SecretKey symmetricKey)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
			NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
		{
			super(symmetricKey);
		}

		@Override
		public byte[] decrypt(final byte[] encrypted)
		{
			throw new UnsupportedOperationException("not needed for this test");
		}

		@Override
		protected Cipher newCipher(final SecretKey key, final String algorithm, final byte[] salt,
			final int iterationCount, final int operationMode)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException
		{
			return newCipher(operationMode, key, newAlgorithmParameterSpec(salt, iterationCount),
				algorithm);
		}
	}
}
