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
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.algorithm.HashAlgorithm;
import de.alpharogroup.crypto.hash.HashExtensions;
import de.alpharogroup.crypto.hex.HexableEncryptor;
import lombok.experimental.UtilityClass;

import com.google.common.primitives.Longs;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.ArrayUtils;

/**
 * The class {@link Hasher}
 *
 * @author Asterios Raptis
 */
@UtilityClass
public class Hasher
{

	/**
	 * Hashes and hex it with the given {@link String} object with the given parameters.
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
		final HashAlgorithm hashAlgorithm, final Charset charset)
		throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException,
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
		InvalidKeySpecException, InvalidAlgorithmParameterException
	{
		final HexableEncryptor hexEncryptor = new HexableEncryptor(CryptConst.PRIVATE_KEY);
		return hexEncryptor.encrypt(HashExtensions.hash(hashIt, salt, hashAlgorithm, charset));
	}
	
    /**
     * Calculates the SHA256-hash as byte array from the given fields
     * @param input the input hash
     * @param  hash the merkle
     * @param signature the signature
     * @param timestamp the timestamp
     * @return the calculated SHA256-hash as byte array
     */
    public static byte[] calculateHashValue(byte[] input, byte[] hash, byte[] signature, long timestamp) {
        byte[] hashValue = ArrayUtils.addAll(input, hash);
        hashValue = ArrayUtils.addAll(hashValue, signature);
        hashValue = ArrayUtils.addAll(hashValue, Longs.toByteArray(timestamp));
        return DigestUtils.sha256(hashValue);
    }

}
