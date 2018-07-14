/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto.pw;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import de.alpharogroup.crypto.algorithm.HashAlgorithm;
import de.alpharogroup.crypto.hash.HashExtensions;
import de.alpharogroup.crypto.sha.Hasher;
import de.alpharogroup.random.RandomExtensions;
import de.alpharogroup.random.RandomObjectsExtensions;

/**
 * The class {@link PasswordEncryptor} is a singleton and helps to generate secure encrypted random
 * passwords.
 *
 * @author Asterios Raptis
 */
public class PasswordEncryptor implements Serializable
{

	/**
	 * The serialVersionUID.
	 */
	private static final long serialVersionUID = -4667877106378932018L;

	/** The single instance from the {@link PasswordEncryptor}. */
	private static final PasswordEncryptor instance = new PasswordEncryptor();

	/**
	 * Gets the single instance of the {@link PasswordEncryptor} object.
	 *
	 * @return single instance of {@link PasswordEncryptor}
	 */
	public static PasswordEncryptor getInstance()
	{
		return instance;
	}

	/** The default algorithm. */
	private final HashAlgorithm DEFAULT_ALGORITHM = HashAlgorithm.SHA_512;

	/** The default charset. */
	private final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");

	/**
	 * Private constructor. Instantiates a new {@link PasswordEncryptor} object.
	 */
	private PasswordEncryptor()
	{
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
		return RandomObjectsExtensions.getRandomPassword(length);
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
		return RandomObjectsExtensions.getRandomPassword(length);
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
		return new String(RandomExtensions.getRandomSalt(length, DEFAULT_CHARSET), DEFAULT_CHARSET);
	}

	/**
	 * Hash and hex password with the given salt.
	 *
	 * @param password
	 *            the password
	 * @param salt
	 *            the salt
	 * @return the generated {@link String} object
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown by get the byte array of the private key String object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeyException
	 *             the invalid key exception is thrown if initialization of the cypher object fails.
	 * @throws BadPaddingException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws IllegalBlockSizeException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 */
	public String hashAndHexPassword(final String password, final String salt)
		throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException,
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
		InvalidKeySpecException, InvalidAlgorithmParameterException
	{
		return hashAndHexPassword(password, salt, DEFAULT_ALGORITHM, DEFAULT_CHARSET);
	}

	/**
	 * Hash and hex the given password with the given salt, hash algorithm and charset.
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
	 * @throws UnsupportedEncodingException
	 *             is thrown by get the byte array of the private key String object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeyException
	 *             the invalid key exception is thrown if initialization of the cypher object fails.
	 * @throws BadPaddingException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws IllegalBlockSizeException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 */
	public String hashAndHexPassword(final String password, final String salt,
		final HashAlgorithm hashAlgorithm, final Charset charset)
		throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException,
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
		InvalidKeySpecException, InvalidAlgorithmParameterException
	{
		final String hashedPassword = Hasher.hashAndHex(password, salt, hashAlgorithm, charset);
		return hashedPassword;
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
	 *             the no such algorithm exception
	 */
	public String hashPassword(final String password, final String salt,
		final HashAlgorithm hashAlgorithm, final Charset charset) throws NoSuchAlgorithmException
	{
		final String hashedPassword = HashExtensions.hash(password, salt, hashAlgorithm, charset);
		return hashedPassword;
	}

	/**
	 * Matches the given strings and returns true if they are equal.
	 *
	 * @param hashedPassword
	 *            the hashed password
	 * @param dbHashedPassword
	 *            the db hashed password
	 * @return true, if successful
	 */
	public boolean match(final String hashedPassword, final String dbHashedPassword)
	{
		return hashedPassword.equals(dbHashedPassword);
	}

}
