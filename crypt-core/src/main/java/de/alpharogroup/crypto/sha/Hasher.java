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
package de.alpharogroup.crypto.sha;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.aes.HexEncryptor;
import de.alpharogroup.crypto.algorithm.HashAlgorithm;
import de.alpharogroup.random.Constants;
import de.alpharogroup.random.RandomExtensions;

/**
 * The Class Hasher.
 *
 * @author Asterios Raptis
 */
public class Hasher
{

	/**
	 * Gets the random salt.
	 *
	 * @param length
	 *            the length
	 * @param charset
	 *            the charset
	 * @return the random salt
	 */
	public static byte[] getRandomSalt(final int length, final Charset charset)
	{
		return RandomExtensions.getRandomString(Constants.LCUCCHARSWN, length).getBytes(charset);
	}

	/**
	 * Hash.
	 *
	 * @param hashIt
	 *            the hash it
	 * @param salt
	 *            the salt
	 * @param hashAlgorithm
	 *            the hash algorithm
	 * @param charset
	 *            the charset
	 * @return the string
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails.
	 */
	public static String hash(final String hashIt, final String salt,
		final HashAlgorithm hashAlgorithm, final Charset charset) throws NoSuchAlgorithmException
	{
		final MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm.getAlgorithm());
		messageDigest.reset();
		messageDigest.update(salt.getBytes(charset));
		return new String(messageDigest.digest(hashIt.getBytes(charset)), charset);
	}

	public static String hashAndBase64(final String hashIt, final String salt,
		final HashAlgorithm hashAlgorithm, final Charset charset) throws NoSuchAlgorithmException
	{
		final String hashedAndBase64 = new Base64().encodeToString(hash(hashIt, salt,
			hashAlgorithm, charset).getBytes(charset));
		return hashedAndBase64;
	}

	/**
	 * Hash and hex.
	 *
	 * @param hashIt
	 *            the hash it
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
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 */
	public static String hashAndHex(final String hashIt, final String salt,
		final HashAlgorithm hashAlgorithm, final Charset charset) throws NoSuchAlgorithmException,
		InvalidKeyException, UnsupportedEncodingException, NoSuchPaddingException,
		IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, InvalidAlgorithmParameterException
	{
		final HexEncryptor hexEncryptor = new HexEncryptor(CryptConst.PRIVATE_KEY);
		return hexEncryptor.encrypt(hash(hashIt, salt, hashAlgorithm, charset));
	}

}
