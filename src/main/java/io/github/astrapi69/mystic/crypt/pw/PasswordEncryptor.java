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

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import io.github.astrapi69.crypt.api.algorithm.HashAlgorithm;
import io.github.astrapi69.crypt.data.hash.HashExtensions;
import io.github.astrapi69.mystic.crypt.sha.Hasher;
import io.github.astrapi69.random.object.RandomObjectFactory;
import io.github.astrapi69.random.object.RandomWebObjectFactory;

/**
 * The class {@link PasswordEncryptor} is a singleton and helps to generate secure encrypted random
 * passwords.
 *
 * @author Asterios Raptis
 */
public class PasswordEncryptor implements Serializable
{

	/** The single instance from the {@link PasswordEncryptor}. */
	private static final PasswordEncryptor instance = new PasswordEncryptor();

	/**
	 * The serialVersionUID.
	 */
	private static final long serialVersionUID = -4667877106378932018L;
	/** The default algorithm. */
	private final HashAlgorithm DEFAULT_ALGORITHM = HashAlgorithm.SHA_512;
	/**
	 * The default charset. Declared static because it is a constant, not per-instance state:
	 * {@link Charset} is not serializable, so as an instance field it would have made every attempt
	 * to serialize this class fail with a {@link java.io.NotSerializableException}.
	 */
	private static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");

	/**
	 * Private constructor. Instantiates a new {@link PasswordEncryptor} object.
	 */
	private PasswordEncryptor()
	{
	}

	/**
	 * Gets the single instance of the {@link PasswordEncryptor} object.
	 *
	 * @return single instance of {@link PasswordEncryptor}
	 */
	public static PasswordEncryptor getInstance()
	{
		return instance;
	}

	/**
	 * Gets a random password.
	 *
	 * @param length
	 *            the length
	 * @return the new secure random password
	 */
	public String getRandomPassword(final int length)
	{
		return RandomWebObjectFactory.randomPassword(length);
	}

	/**
	 * Gets a random password.
	 *
	 * @param length
	 *            the length
	 * @return the new secure random password
	 */
	public String getRandomPassword(final Optional<Integer> length)
	{
		return RandomWebObjectFactory.randomPassword(length);
	}

	/**
	 * Gets the random salt.
	 *
	 * @return the random salt
	 */
	public String getRandomSalt()
	{
		return getRandomSalt(8);
	}

	/**
	 * Gets a random salt string.
	 *
	 * @param length
	 *            the length
	 * @return the random salt string.
	 */
	public String getRandomSalt(final int length)
	{
		return new String(RandomObjectFactory.randomSalt(length, DEFAULT_CHARSET), DEFAULT_CHARSET);
	}

	/**
	 * Hash and hex the given password with the given private key, salt, hash algorithm and charset.
	 * Unlike the removed {@code hashAndHexPassword(password, salt)} convenience overloads, this
	 * method requires the caller to supply their own secret key rather than silently using a
	 * hardcoded, publicly known default.
	 *
	 * @param password
	 *            the password
	 * @param privateKey
	 *            the private key used to encrypt the digest
	 * @param salt
	 *            the salt
	 * @param hashAlgorithm
	 *            the hash algorithm
	 * @param charset
	 *            the charset
	 * @return the generated {@link String} object
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
	public String hashAndHexPassword(final String password, final String privateKey,
		final String salt, final HashAlgorithm hashAlgorithm, final Charset charset)
		throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException,
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
		InvalidKeySpecException, InvalidAlgorithmParameterException
	{
		return Hasher.hashAndHex(password, privateKey, salt, hashAlgorithm, charset);
	}

	/**
	 * Hashes the given password with the given salt, hash algorithm and charset.
	 *
	 * @param password
	 *            the password
	 * @param salt
	 *            the salt
	 * @param hashAlgorithm
	 *            the hash algorithm
	 * @param charset
	 *            the charset
	 * @return the generated {@link String} object
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails.
	 */
	public String hashPassword(final String password, final String salt,
		final HashAlgorithm hashAlgorithm, final Charset charset) throws NoSuchAlgorithmException
	{
		final String hashedPassword = HashExtensions.hash(password, salt, hashAlgorithm, charset);
		return hashedPassword;
	}

	/**
	 * Matches the given strings and returns true if they are equal. Uses a constant-time comparison
	 * ({@link MessageDigest#isEqual(byte[], byte[])}) rather than {@link String#equals} to avoid
	 * leaking information about the hash via response-time differences.
	 *
	 * @param hashedPassword
	 *            the hashed password
	 * @param dbHashedPassword
	 *            the db hashed password
	 * @return true, if successful
	 */
	public boolean match(final String hashedPassword, final String dbHashedPassword)
	{
		return MessageDigest.isEqual(hashedPassword.getBytes(DEFAULT_CHARSET),
			dbHashedPassword.getBytes(DEFAULT_CHARSET));
	}

	/**
	 * Hashes the given password with Argon2id, a memory-hard password-hashing algorithm suitable
	 * for password storage (unlike {@link #hashPassword(String, String, HashAlgorithm, Charset)},
	 * which uses a general-purpose hash function that is deliberately fast - the opposite of what
	 * password hashing needs). A fresh random salt is generated per call; the salt and parameters
	 * are encoded together with the hash in the returned string (PHC format), so
	 * {@link #matchArgon2id(String, String)} needs only the password and this string to verify.
	 *
	 * @param password
	 *            the password
	 * @return the encoded Argon2id hash
	 */
	public String hashPasswordArgon2id(final String password)
	{
		return Argon2Support.hash(password.toCharArray());
	}

	/**
	 * Verifies the given password against a hash previously produced by
	 * {@link #hashPasswordArgon2id(String)}.
	 *
	 * @param password
	 *            the password to check
	 * @param encodedHash
	 *            the encoded Argon2id hash to check against
	 * @return true if the password matches
	 */
	public boolean matchArgon2id(final String password, final String encodedHash)
	{
		return Argon2Support.verify(password.toCharArray(), encodedHash);
	}

	/**
	 * Hashes the given password with PBKDF2-HMAC-SHA256. A fresh random salt is generated per call;
	 * the salt and iteration count are encoded together with the hash in the returned string, so
	 * {@link #matchPbkdf2(String, String)} needs only the password and this string to verify.
	 * <p>
	 * Prefer {@link #hashPasswordArgon2id(String)} for new code: PBKDF2 is not memory-hard and is
	 * comparatively cheap to attack in parallel on GPUs/ASICs even at a high iteration count. This
	 * method exists for interop with systems that specifically require PBKDF2.
	 *
	 * @param password
	 *            the password
	 * @return the encoded PBKDF2 hash
	 */
	public String hashPasswordPbkdf2(final String password)
	{
		return Pbkdf2Support.hash(password.toCharArray());
	}

	/**
	 * Verifies the given password against a hash previously produced by
	 * {@link #hashPasswordPbkdf2(String)}.
	 *
	 * @param password
	 *            the password to check
	 * @param encodedHash
	 *            the encoded PBKDF2 hash to check against
	 * @return true if the password matches
	 */
	public boolean matchPbkdf2(final String password, final String encodedHash)
	{
		return Pbkdf2Support.verify(password.toCharArray(), encodedHash);
	}

}
