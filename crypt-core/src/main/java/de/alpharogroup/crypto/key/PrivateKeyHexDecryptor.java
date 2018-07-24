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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.DecoderException;

import de.alpharogroup.crypto.algorithm.KeyPairWithModeAndPaddingAlgorithm;
import de.alpharogroup.crypto.hex.HexExtensions;
import de.alpharogroup.crypto.simple.SimpleDecryptor;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;

/**
 * The class {@link PrivateKeyHexDecryptor} decrypts encrypted characters the was encrypted with the
 * public key of the pendant private key of this class.
 */
public class PrivateKeyHexDecryptor
{
	/**
	 * The Cipher object.
	 */
	@Getter
	@Setter
	private Cipher cipher = null;

	/**
	 * The flag initialized that indicates if the cypher is initialized for decryption.
	 *
	 * @return true, if is initialized
	 */
	@Getter(value = AccessLevel.PRIVATE)
	private boolean initialized;

	/**
	 * The private key.
	 */
	@Getter
	@Setter
	private PrivateKey privateKey = null;

	/**
	 * Instantiates a new {@link PrivateKeyHexDecryptor} with the given {@link PrivateKey}.
	 *
	 * @param privateKey
	 *            The private key.
	 */
	public PrivateKeyHexDecryptor(final PrivateKey privateKey)
	{
		this.setPrivateKey(privateKey);
	}

	/**
	 * Decrypt the given encrypted String.
	 *
	 * @param encypted
	 *            The String to decrypt.
	 * @return The decrypted String
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeyException
	 *             the invalid key exception is thrown if initialization of the cypher object fails.
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
	 *             is thrown if initialization of the cypher object fails.
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

	/**
	 * Initializes the {@link SimpleDecryptor} object.
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeyException
	 *             the invalid key exception is thrown if initialization of the cypher object fails.
	 * @throws InvalidKeySpecException
	 * @throws IOException
	 * @throws InvalidAlgorithmParameterException
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
		}
	}

}
