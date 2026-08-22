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
package io.github.astrapi69.mystic.crypt.pw;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.api.algorithm.HashAlgorithm;

/**
 * The unit test class for the class {@link PasswordEncryptor}
 */
public class PasswordEncryptorTest
{

	PasswordEncryptor instance;

	@BeforeEach
	protected void setUp()
	{
		instance = PasswordEncryptor.getInstance();
	}

	/**
	 * Test method for {@link PasswordEncryptor#getInstance()}
	 */
	@Test
	public void testGetInstance()
	{
		assertNotNull(instance);
	}

	/**
	 * Test method for {@link PasswordEncryptor#getRandomPassword(int)}
	 */
	@Test
	public void testGetRandomPasswordInt()
	{
		String randomPassword = instance.getRandomPassword(8);
		assertNotNull(randomPassword);
		assertEquals(8, randomPassword.length());
	}

	/**
	 * Test method for {@link PasswordEncryptor#getRandomPassword(Optional)}
	 */
	@Test
	public void testGetRandomPasswordOptionalOfInteger()
	{
		String randomPassword = instance.getRandomPassword(Optional.of(8));
		assertNotNull(randomPassword);
		assertEquals(8, randomPassword.length());
	}

	/**
	 * Test method for {@link PasswordEncryptor#getRandomSalt()}
	 */
	@Test
	public void testGetRandomSalt()
	{
		String randomSalt = instance.getRandomSalt();
		assertNotNull(randomSalt);
		assertEquals(8, randomSalt.length());
	}

	/**
	 * Test method for {@link PasswordEncryptor#getRandomSalt(int)}
	 */
	@Test
	public void testGetRandomSaltInt()
	{
		String randomSalt = instance.getRandomSalt(8);
		assertNotNull(randomSalt);
		assertEquals(8, randomSalt.length());
	}

	/**
	 * Test method for
	 * {@link PasswordEncryptor#hashAndHexPassword(String, String, String, HashAlgorithm, Charset)}
	 *
	 * <p>
	 * Replaces the removed {@code hashAndHexPassword(password, salt)}/
	 * {@code hashAndHexPassword(password, salt, hashAlgorithm, charset)} overloads, which silently
	 * used a hardcoded, publicly known key. The new overload requires an explicit private key and -
	 * since the underlying {@link io.github.astrapi69.mystic.crypt.hex.HexableEncryptor} now uses a
	 * fresh random GCM nonce per call - produces different ciphertext on every call even for
	 * identical inputs, and a different private key must produce a different result too.
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown by get the byte array of the private key String object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws InvalidKeyException
	 *             the invalid key exception is thrown if initialization of the cipher object fails.
	 * @throws BadPaddingException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws IllegalBlockSizeException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 */
	@Test
	public void testHashAndHexPasswordWithExplicitPrivateKey()
		throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException,
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
		InvalidKeySpecException, InvalidAlgorithmParameterException
	{
		String salt = "uLc34JGr";
		String password = "foo";
		String firstPrivateKey = "1234567890123456";
		String secondPrivateKey = "6543210987654321";
		HashAlgorithm hashAlgorithm = HashAlgorithm.SHA_512;
		Charset charset = StandardCharsets.UTF_8;

		String first = instance.hashAndHexPassword(password, firstPrivateKey, salt, hashAlgorithm,
			charset);
		String second = instance.hashAndHexPassword(password, firstPrivateKey, salt, hashAlgorithm,
			charset);
		assertNotEquals(first, second);

		String withDifferentKey = instance.hashAndHexPassword(password, secondPrivateKey, salt,
			hashAlgorithm, charset);
		assertNotEquals(first, withDifferentKey);
	}

	/**
	 * Test method for
	 * {@link PasswordEncryptor#hashPassword(String, String, HashAlgorithm, Charset)}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails.
	 */
	@Test
	public void testHashPassword() throws NoSuchAlgorithmException
	{
		String actual;
		String salt;
		String password;
		HashAlgorithm hashAlgorithm;
		Charset charset;
		salt = "uLc34JGr";
		password = "foo";
		hashAlgorithm = HashAlgorithm.SHA_1;
		charset = StandardCharsets.UTF_8;
		actual = instance.hashPassword(password, salt, hashAlgorithm, charset);
		assertNotNull(actual);
		// guard against a mutant that returns an empty string: the hash must be the SHA-1 digest
		// of the salted password, deterministic for the same inputs and matchable
		String expected = io.github.astrapi69.crypt.data.hash.HashExtensions.hash(password, salt,
			hashAlgorithm, charset);
		assertEquals(expected, actual);
		assertTrue(actual.length() > 0);
		assertTrue(
			instance.match(actual, instance.hashPassword(password, salt, hashAlgorithm, charset)));
	}

	/**
	 * Test method for {@link PasswordEncryptor#hashPasswordArgon2id(String)} and
	 * {@link PasswordEncryptor#matchArgon2id(String, String)}
	 */
	@Test
	public void testHashPasswordArgon2idAndMatch()
	{
		String password = "correct horse battery staple";

		String encoded = instance.hashPasswordArgon2id(password);
		assertNotNull(encoded);
		assertTrue(encoded.startsWith("$argon2id$"));

		assertTrue(instance.matchArgon2id(password, encoded));
		assertFalse(instance.matchArgon2id("wrong password", encoded));
	}

	/**
	 * Test method for {@link PasswordEncryptor#hashPasswordArgon2id(String)}
	 *
	 * <p>
	 * A random salt is generated per call, so hashing the same password twice must produce
	 * different encoded output.
	 */
	@Test
	public void testHashPasswordArgon2idTwiceProducesDifferentOutput()
	{
		String password = "correct horse battery staple";

		String first = instance.hashPasswordArgon2id(password);
		String second = instance.hashPasswordArgon2id(password);

		assertNotEquals(first, second);
		assertTrue(instance.matchArgon2id(password, first));
		assertTrue(instance.matchArgon2id(password, second));
	}

	/**
	 * Test method for {@link PasswordEncryptor#matchArgon2id(String, String)}
	 *
	 * <p>
	 * A malformed/tampered encoded hash must fail to match rather than throw.
	 */
	@Test
	public void testMatchArgon2idWithTamperedEncodedHashFails()
	{
		String password = "correct horse battery staple";
		String encoded = instance.hashPasswordArgon2id(password);
		String tampered = encoded.substring(0, encoded.length() - 4) + "abcd";

		assertFalse(instance.matchArgon2id(password, tampered));
	}

	/**
	 * Test method for {@link PasswordEncryptor#match(String, String)}
	 */
	@Test
	public void testMatch()
	{
		assertTrue(instance.match("hash-value", "hash-value"));
		assertFalse(instance.match("hash-value", "other-value"));
	}

	/**
	 * Test method for {@link PasswordEncryptor#hashPasswordPbkdf2(String)} and
	 * {@link PasswordEncryptor#matchPbkdf2(String, String)}
	 */
	@Test
	public void hashPasswordPbkdf2_createsAHashThatOnlyMatchesTheSamePassword()
	{
		String encodedHash = instance.hashPasswordPbkdf2("secret-password");

		assertNotNull(encodedHash);
		assertTrue(instance.matchPbkdf2("secret-password", encodedHash));
		assertFalse(instance.matchPbkdf2("another-password", encodedHash));
	}

	/**
	 * Test method for {@link PasswordEncryptor#hashPasswordPbkdf2(String)}, every hash of the same
	 * password is salted individually
	 */
	@Test
	public void hashPasswordPbkdf2_isSaltedAndThereforeNotDeterministic()
	{
		String firstHash = instance.hashPasswordPbkdf2("secret-password");
		String secondHash = instance.hashPasswordPbkdf2("secret-password");

		assertNotEquals(firstHash, secondHash);
		assertTrue(instance.matchPbkdf2("secret-password", firstHash));
		assertTrue(instance.matchPbkdf2("secret-password", secondHash));
	}
}
