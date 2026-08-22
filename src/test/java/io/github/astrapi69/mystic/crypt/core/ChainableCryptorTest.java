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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.api.Decryptor;
import io.github.astrapi69.crypt.api.Encryptor;

/**
 * The unit test class for the classes {@link ChainableEncryptor} and {@link ChainableDecryptor}
 */
public class ChainableCryptorTest
{

	private static final Encryptor<String, String> APPEND_ONE = toEncrypt -> toEncrypt + "1";

	private static final Encryptor<String, String> APPEND_TWO = toEncrypt -> toEncrypt + "2";

	private static final Decryptor<String, String> REMOVE_LAST = encrypted -> encrypted.substring(0,
		encrypted.length() - 1);

	private static class StringChainEncryptor extends ChainableEncryptor<String>
	{
		// [varargs] the array reference is only forwarded to the @SafeVarargs constructor of
		// ChainableEncryptor; this test fixture neither writes into it, nor stores it, nor
		// returns it
		@SafeVarargs
		@SuppressWarnings("varargs")
		StringChainEncryptor(final Encryptor<String, String>... encryptors)
		{
			super(encryptors);
		}
	}

	private static class StringChainDecryptor extends ChainableDecryptor<String>
	{
		// [varargs] the array reference is only forwarded to the @SafeVarargs constructor of
		// ChainableDecryptor; this test fixture neither writes into it, nor stores it, nor
		// returns it
		@SafeVarargs
		@SuppressWarnings("varargs")
		StringChainDecryptor(final Decryptor<String, String>... decryptors)
		{
			super(decryptors);
		}
	}

	/**
	 * Test method for {@link ChainableEncryptor#encrypt(Object)}, every encryptor of the chain has
	 * to be applied in the given order
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void encrypt_appliesEveryEncryptorOfTheChainInOrder() throws Exception
	{
		StringChainEncryptor encryptor = new StringChainEncryptor(APPEND_ONE, APPEND_TWO);

		assertEquals("foo12", encryptor.encrypt("foo"));
	}

	/**
	 * Test method for {@link ChainableEncryptor#getEncryptors()}, the chained encryptors are
	 * answered in the given order
	 */
	@Test
	public void getEncryptors_answersTheChainedEncryptors()
	{
		StringChainEncryptor encryptor = new StringChainEncryptor(APPEND_ONE, APPEND_TWO);

		assertArrayEquals(new Object[] { APPEND_ONE, APPEND_TWO }, encryptor.getEncryptors());
	}

	/**
	 * Test method for {@link ChainableDecryptor#decrypt(Object)}, every decryptor of the chain has
	 * to be applied in the given order
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void decrypt_appliesEveryDecryptorOfTheChainInOrder() throws Exception
	{
		StringChainDecryptor decryptor = new StringChainDecryptor(REMOVE_LAST, REMOVE_LAST);

		assertEquals("foo", decryptor.decrypt("foo12"));
	}

	/**
	 * Test method for {@link ChainableDecryptor#getDecryptors()}, the chained decryptors are
	 * answered in the given order
	 */
	@Test
	public void getDecryptors_answersTheChainedDecryptors()
	{
		StringChainDecryptor decryptor = new StringChainDecryptor(REMOVE_LAST, REMOVE_LAST);

		assertArrayEquals(new Object[] { REMOVE_LAST, REMOVE_LAST }, decryptor.getDecryptors());
	}
}
