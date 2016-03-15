/**
 * Copyright (C) 2007 Asterios Raptis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.alpharogroup.crypto.pw;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import de.alpharogroup.crypto.algorithm.HashAlgorithm;
import de.alpharogroup.crypto.sha.Hasher;
import de.alpharogroup.random.RandomObjectsExtensions;


/**
 * The Class PasswordEncryptor is a singleton and helps to generate secure encrypted random
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

	/** The single instance from the PasswordService. */
	private static final PasswordEncryptor instance = new PasswordEncryptor();

	/**
	 * Gets the single instance of PasswordService.
	 *
	 * @return single instance of PasswordService
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
	 * Private constructor. Instantiates a new password service.
	 */
	private PasswordEncryptor()
	{
		super();
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
	 * Gets a random salt string.
	 *
	 * @param length
	 *            the length
	 * @return the random salt string.
	 */
	public String getRandomSalt(final int length)
	{
		return new String(Hasher.getRandomSalt(length, DEFAULT_CHARSET), DEFAULT_CHARSET);
	}

	/**
	 * Hash and hex password with the given salt.
	 *
	 * @param password
	 *            the password
	 * @param salt
	 *            the salt
	 * @return the string
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
	 */
	public String hashAndHexPassword(final String password, final String salt)
		throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException,
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
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
	 * @return the string
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
	 */
	public String hashAndHexPassword(final String password, final String salt,
		final HashAlgorithm hashAlgorithm, final Charset charset) throws NoSuchAlgorithmException,
		InvalidKeyException, UnsupportedEncodingException, NoSuchPaddingException,
		IllegalBlockSizeException, BadPaddingException
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
	 * @return the string
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 */
	public String hashPassword(final String password, final String salt,
		final HashAlgorithm hashAlgorithm, final Charset charset) throws NoSuchAlgorithmException
	{
		final String hashedPassword = Hasher.hash(password, salt, hashAlgorithm, charset);
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
