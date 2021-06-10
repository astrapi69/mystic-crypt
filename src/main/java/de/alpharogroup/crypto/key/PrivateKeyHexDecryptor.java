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
package de.alpharogroup.crypto.key;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;

import io.github.astrapi69.crypto.algorithm.KeyPairWithModeAndPaddingAlgorithm;
import io.github.astrapi69.crypto.hex.HexExtensions;

/**
 * The class {@link PrivateKeyHexDecryptor} decrypts encrypted characters the was encrypted with the
 * public key of the pendant private key of this class.
 */
public final class PrivateKeyHexDecryptor
{
	/**
	 * The Cipher object
	 */
	private Cipher cipher;

	/**
	 * The flag initialized that indicates if the cipher is initialized for decryption.
	 *
	 * @return true, if is initialized
	 */
	private boolean initialized;

	/**
	 * The private key
	 */
	private final PrivateKey privateKey;

	/**
	 * Instantiates a new {@link PrivateKeyHexDecryptor} with the given {@link PrivateKey}
	 *
	 * @param privateKey
	 *            The private key
	 */
	public PrivateKeyHexDecryptor(final PrivateKey privateKey)
	{
		Objects.requireNonNull(privateKey);
		this.privateKey = privateKey;
	}

	/**
	 * Decrypt the given encrypted {@link String}
	 *
	 * @param encypted
	 *            The encrypted {@link String} to decrypt
	 * @return The decrypted {@link String}
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws InvalidKeyException
	 *             the invalid key exception is thrown if initialization of the cipher object fails.
	 * @throws DecoderException
	 *             is thrown if an odd number or illegal of characters is supplied
	 * @throws IllegalBlockSizeException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws BadPaddingException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 */
	public String decrypt(final String encypted)
		throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
		DecoderException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException,
		InvalidAlgorithmParameterException, IOException
	{
		initialize();
		final byte[] dec = HexExtensions.decodeHex(encypted.toCharArray());
		final byte[] utf8 = this.cipher.doFinal(dec);
		return new String(utf8, "UTF-8");
	}

	public Cipher getCipher()
	{
		return this.cipher;
	}

	public PrivateKey getPrivateKey()
	{
		return this.privateKey;
	}

	/**
	 * Initializes the {@link PrivateKeyHexDecryptor} object
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws InvalidKeyException
	 *             the invalid key exception is thrown if initialization of the cipher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 */
	private void initialize()
		throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
		InvalidKeySpecException, IOException, InvalidAlgorithmParameterException
	{
		if (!isInitialized())
		{
			cipher = Cipher
				.getInstance(KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA1AndMGF1Padding
					.getAlgorithm());
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			initialized = true;
		}
	}

	private boolean isInitialized()
	{
		return this.initialized;
	}
}
