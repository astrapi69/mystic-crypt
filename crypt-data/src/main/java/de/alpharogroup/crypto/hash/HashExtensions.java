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
package de.alpharogroup.crypto.hash;

import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Queue;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.ArrayUtils;

import com.google.common.primitives.Longs;

import de.alpharogroup.crypto.algorithm.HashAlgorithm;
import lombok.NonNull;
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

	/**
	 * Calculates the hash value as byte array from the given fields
	 *
	 * @param input
	 *            the input hash
	 * @param hash
	 *            the merkle
	 * @param signature
	 *            the signature
	 * @param timestamp
	 *            the timestamp
	 * @param algorithm
	 *            the hash algorithm
	 * @return the calculated hash as byte array
	 */
	public static byte[] hash(byte[] input, byte[] hash, byte[] signature, long timestamp,
		@NonNull HashAlgorithm algorithm)
	{
		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, signature);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		switch (algorithm)
		{
			case SHA1 :
				return DigestUtils.sha1(hashValue);
			case SHA256 :
				return DigestUtils.sha256(hashValue);
			case SHA384 :
				return DigestUtils.sha384(hashValue);
			case SHA512 :
				return DigestUtils.sha512(hashValue);
			case SHA_1 :
				return DigestUtils.sha1(hashValue);
			case SHA_256 :
				return DigestUtils.sha256(hashValue);
			case SHA_384 :
				return DigestUtils.sha384(hashValue);
			case SHA_512 :
				return DigestUtils.sha512(hashValue);
			default :
				return DigestUtils.sha256(hashValue);
		}
	}

	/**
	 * Calculates the hash value as byte array from the given fields
	 *
	 * @param input
	 *            the input hash
	 * @param hash
	 *            the merkle
	 * @param signature
	 *            the signature
	 * @param timestamp
	 *            the timestamp
	 * @param algorithm
	 *            the hash algorithm
	 * @return the calculated hash as byte array
	 */
	public static byte[] hash(byte[] input, byte[] hash, long signature, long timestamp,
		@NonNull HashAlgorithm algorithm)
	{
		byte[] hashValue = ArrayUtils.addAll(input, hash);
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(signature));
		hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
		switch (algorithm)
		{
			case SHA1 :
				return DigestUtils.sha1(hashValue);
			case SHA256 :
				return DigestUtils.sha256(hashValue);
			case SHA384 :
				return DigestUtils.sha384(hashValue);
			case SHA512 :
				return DigestUtils.sha512(hashValue);
			case SHA_1 :
				return DigestUtils.sha1(hashValue);
			case SHA_256 :
				return DigestUtils.sha256(hashValue);
			case SHA_384 :
				return DigestUtils.sha384(hashValue);
			case SHA_512 :
				return DigestUtils.sha512(hashValue);
			default :
				return DigestUtils.sha256(hashValue);
		}
	}

	/**
	 * Calculates the hash value as byte array from the given fields
	 *
	 * @param input
	 *            the input hash
	 * @param publicKey
	 *            the public key
	 * @param algorithm
	 *            the algorithm
	 * @return the calculated hash as byte array
	 */
	public static byte[] hash(byte[] input, byte[] publicKey, @NonNull HashAlgorithm algorithm)
	{
		byte[] hashValue = ArrayUtils.addAll(input, publicKey);
		switch (algorithm)
		{
			case SHA1 :
				return DigestUtils.sha1(hashValue);
			case SHA256 :
				return DigestUtils.sha256(hashValue);
			case SHA384 :
				return DigestUtils.sha384(hashValue);
			case SHA512 :
				return DigestUtils.sha512(hashValue);
			case SHA_1 :
				return DigestUtils.sha1(hashValue);
			case SHA_256 :
				return DigestUtils.sha256(hashValue);
			case SHA_384 :
				return DigestUtils.sha384(hashValue);
			case SHA_512 :
				return DigestUtils.sha512(hashValue);
			default :
				return DigestUtils.sha256(hashValue);
		}
	}

	/**
	 * Gets the hash value of the given queue and the given algorithm.
	 * 
	 * @see <a href="https://en.wikipedia.org/wiki/Merkle_tree">wikipedia Merkle tree</a>
	 *
	 * @param hashQueue
	 *            the hash queue
	 * @param algorithm
	 *            the algorithm
	 * @return the merkle root tree
	 */
	public static byte[] getMerkleRootHash(Queue<byte[]> hashQueue,
		@NonNull HashAlgorithm algorithm)
	{
		while (hashQueue.size() > 1)
		{
			byte[] hashValue = ArrayUtils.addAll(hashQueue.poll(), hashQueue.poll());
			switch (algorithm)
			{
				case SHA1 :
					hashQueue.add(DigestUtils.sha1(hashValue));
				case SHA256 :
					hashQueue.add(DigestUtils.sha256(hashValue));
				case SHA384 :
					hashQueue.add(DigestUtils.sha384(hashValue));
				case SHA512 :
					hashQueue.add(DigestUtils.sha512(hashValue));
				case SHA_1 :
					hashQueue.add(DigestUtils.sha1(hashValue));
				case SHA_256 :
					hashQueue.add(DigestUtils.sha256(hashValue));
				case SHA_384 :
					hashQueue.add(DigestUtils.sha384(hashValue));
				case SHA_512 :
					hashQueue.add(DigestUtils.sha512(hashValue));
				default :
					hashQueue.add(DigestUtils.sha256(hashValue));
			}
		}
		return hashQueue.poll();
	}

}
