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
package de.alpharogroup.crypto.hash;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Base64;

import de.alpharogroup.crypto.algorithm.HashAlgorithm;
import lombok.experimental.UtilityClass;

/**
 * The class {@link HashExtensions}.
 *
 * @author Asterios Raptis
 */
@UtilityClass
public class HashExtensions
{

	/**
	 * Hashes the given {@link byte[]} object with the given parameters.
	 *
	 * @param hashIt
	 *            the hash it
	 * @param hashAlgorithm
	 *            the hash algorithm
	 * @return the generated {@link String} object
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the MessageDigest object fails.
	 */
	public static byte[] hash(final byte[] hashIt, final HashAlgorithm hashAlgorithm)
		throws NoSuchAlgorithmException
	{
		return hash(hashIt, null, hashAlgorithm, null);
	}

	/**
	 * Hashes the given {@link byte[]} object with the given parameters.
	 *
	 * @param hashIt
	 *            the hash it
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
	public static byte[] hash(final byte[] hashIt, final String salt,
		final HashAlgorithm hashAlgorithm, final Charset charset) throws NoSuchAlgorithmException
	{
		final MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm.getAlgorithm());
		messageDigest.reset();
		if (salt != null)
		{
			messageDigest.update(salt.getBytes(charset));
		}
		messageDigest.update(hashIt);
		byte[] digestBytes = messageDigest.digest();
		return digestBytes;
	}

	/**
	 * Hashes the given {@link String} object with the given parameters.
	 *
	 * @param hashIt
	 *            the hash it
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
	public static String hash(final String hashIt, final String salt,
		final HashAlgorithm hashAlgorithm, final Charset charset) throws NoSuchAlgorithmException
	{
		final MessageDigest messageDigest = MessageDigest.getInstance(hashAlgorithm.getAlgorithm());
		messageDigest.reset();
		messageDigest.update(salt.getBytes(charset));
		return new String(messageDigest.digest(hashIt.getBytes(charset)), charset);
	}

	/**
	 * Hashes and encodes it with base64 from the given {@link String} object with the given
	 * parameters.
	 *
	 * @param hashIt
	 *            the hash it
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
	public static String hashAndBase64(final String hashIt, final String salt,
		final HashAlgorithm hashAlgorithm, final Charset charset) throws NoSuchAlgorithmException
	{
		final String hashedAndBase64 = new Base64()
			.encodeToString(hash(hashIt, salt, hashAlgorithm, charset).getBytes(charset));
		return hashedAndBase64;
	}

}
