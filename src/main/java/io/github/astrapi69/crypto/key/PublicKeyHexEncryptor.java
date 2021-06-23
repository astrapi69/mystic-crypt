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
package io.github.astrapi69.crypto.key;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Hex;

import io.github.astrapi69.crypto.algorithm.KeyPairWithModeAndPaddingAlgorithm;

/**
 * The class {@link PublicKeyHexEncryptor} can encrypt characters with his public key. <br>
 * <br>
 * Note: This class encrypts directly with the public key so you have to consider the length of the
 * encrypted data. As from the RSA documentation are described of the RSA algorithm can only encrypt
 * data that has a maximum byte length of he RSA key length in bits divided with eight minus eleven
 * padding bytes, i.e. number of maximum bytes = key length in bits / 8 - 11.
 *
 * @deprecated because of the above note this class is tagged as deprecated. Use instead the
 *             corresponding {@link PublicKeyEncryptor}. This class will be removed
 *             in the next major release.
 */
@Deprecated
public final class PublicKeyHexEncryptor
{

	/**
	 * the public key
	 */
	private final PublicKey publicKey;
	/**
	 * the Cipher object
	 */
	private Cipher cipher;
	/**
	 * the flag initialized that indicates if the cipher is initialized for encryption.
	 *
	 * @return true, if is initialized
	 */
	private boolean initialized;

	/**
	 * Instantiates a new {@link PublicKeyHexEncryptor} object with the given {@link PublicKey}
	 *
	 * @param publicKey
	 *            the public key
	 */
	public PublicKeyHexEncryptor(final PublicKey publicKey)
	{
		Objects.requireNonNull(publicKey);
		this.publicKey = publicKey;
	}

	/**
	 * Encrypt the given {@link String} object
	 *
	 * @param string
	 *            The {@link String} to encrypt
	 * @return The encrypted {@link String}
	 *
	 * @throws InvalidKeyException
	 *             the invalid key exception is thrown if initialization of the cipher object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws IllegalBlockSizeException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws BadPaddingException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public String encrypt(final String string)
		throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
		IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, IOException
	{
		initialize();
		final byte[] utf8 = string.getBytes("UTF-8");
		final byte[] encrypt = this.cipher.doFinal(utf8);
		final char[] original = Hex.encodeHex(encrypt, false);
		return new String(original);
	}

	public Cipher getCipher()
	{
		return this.cipher;
	}

	public PublicKey getPublicKey()
	{
		return this.publicKey;
	}

	/**
	 * Initializes this {@link PublicKeyHexEncryptor} object
	 *
	 * @throws UnsupportedEncodingException
	 *             is thrown by get the byte array of the private key String object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws InvalidKeyException
	 *             the invalid key exception is thrown if initialization of the cipher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 */
	private void initialize() throws NoSuchAlgorithmException, InvalidKeySpecException,
		UnsupportedEncodingException, NoSuchPaddingException, InvalidKeyException
	{
		if (!isInitialized())
		{
			cipher = Cipher
				.getInstance(KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA1AndMGF1Padding
					.getAlgorithm());
			cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
			initialized = true;
		}
	}

	private boolean isInitialized()
	{
		return this.initialized;
	}
}
