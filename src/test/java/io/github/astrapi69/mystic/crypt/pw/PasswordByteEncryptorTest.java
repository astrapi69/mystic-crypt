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
package io.github.astrapi69.mystic.crypt.pw;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * The unit test class for the class {@link PasswordByteEncryptor}
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class PasswordByteEncryptorTest
{

	/**
	 * Test method for test the method {@link PasswordByteEncryptor#encrypt(byte[])}
	 *
	 * <p>
	 * A random salt is now generated per call, so the exact ciphertext is no longer deterministic;
	 * assert non-determinism across two calls instead of a golden byte literal.
	 */
	@Test
	public void testEncrypt() throws Exception
	{
		String password = "foo";
		byte[] textBytes = "bar".getBytes(StandardCharsets.UTF_8);
		PasswordByteEncryptor encryptor = new PasswordByteEncryptor(password);

		byte[] first = encryptor.encrypt(textBytes);
		byte[] second = encryptor.encrypt(textBytes);
		assertNotNull(first);
		assertNotNull(second);
		assertFalse(Arrays.equals(first, second));
	}

	/**
	 * Test method for {@link PasswordByteEncryptor#encrypt(byte[])}, the data to encrypt is
	 * mandatory
	 */
	@Test
	public void encrypt_withoutData_throwsANullPointerException()
	{
		PasswordByteEncryptor encryptor = new PasswordByteEncryptor("foo");

		assertThrows(NullPointerException.class, () -> encryptor.encrypt(null));
	}

	/**
	 * Test method for {@link PasswordByteEncryptor#resetPassword()}, after the password is reset
	 * nothing can be encrypted anymore
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void resetPassword_clearsThePasswordSoNothingCanBeEncryptedAnymore() throws Exception
	{
		byte[] textBytes = "bar".getBytes(StandardCharsets.UTF_8);
		PasswordByteEncryptor encryptor = new PasswordByteEncryptor("foo");
		assertNotNull(encryptor.encrypt(textBytes));

		encryptor.resetPassword();

		assertThrows(NullPointerException.class, () -> encryptor.encrypt(textBytes));
	}
}
