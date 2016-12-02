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
package de.alpharogroup.crypto.aes;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import org.apache.commons.codec.DecoderException;

import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.algorithm.Algorithm;
import de.alpharogroup.crypto.interfaces.Decryptor;
import de.alpharogroup.crypto.simple.SimpleDecryptor;

/**
 * Instantiates a new hex decryptor.
 */
@NoArgsConstructor
public class HexDecryptor implements Decryptor
{

	/**
	 * The Cipher object.
	 */
	@Getter
	@Setter
	private Cipher cipher = null;

	/**
	 * The private key.
	 */
	@Getter
	@Setter
	private String privateKey = null;

	/**
	 * The flag initialized that indicates if the cypher is initialized for decryption.
	 *
	 * @return true, if is initialized
	 */
	@Getter(value = AccessLevel.PRIVATE)
	private boolean initialized;

	/**
	 * Constructor with a private key.
	 *
	 * @param privateKey
	 *            The private key.
	 */
	public HexDecryptor(final String privateKey)
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
	 * @throws UnsupportedEncodingException
	 *             is thrown by get the byte array of the private key String object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeyException
	 *             the invalid key exception is thrown if initialization of the cypher object fails.
	 * @throws org.apache.commons.codec.DecoderException
	 *             is thrown if an odd number or illegal of characters is supplied
	 * @throws IllegalBlockSizeException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws BadPaddingException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 */
	@Override
	public String decrypt(final String encypted) throws InvalidKeyException,
		UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException,
		DecoderException, IllegalBlockSizeException, BadPaddingException
	{
		initialize();
		final byte[] dec = HexDump.decodeHex(encypted.toCharArray());
		final byte[] utf8 = this.cipher.doFinal(dec);
		return new String(utf8, "UTF-8");
	}

	/**
	 * Initializes the {@link SimpleDecryptor} object.
	 *
	 * @throws UnsupportedEncodingException
	 *             is thrown by get the byte array of the private key String object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeyException
	 *             the invalid key exception is thrown if initialization of the cypher object fails.
	 */
	private void initialize() throws UnsupportedEncodingException, NoSuchAlgorithmException,
		NoSuchPaddingException, InvalidKeyException
	{
		if (!isInitialized())
		{
			byte[] key;
			if (this.getPrivateKey() != null)
			{
				key = this.getPrivateKey().getBytes("UTF-8");
			}
			else
			{
				key = CryptConst.PRIVATE_KEY.getBytes("UTF-8");
			}
			final SecretKeySpec skeySpec = new SecretKeySpec(key, Algorithm.AES.getAlgorithm());
			this.cipher = Cipher.getInstance(Algorithm.AES.getAlgorithm());
			cipher.init(Cipher.DECRYPT_MODE, skeySpec);
		}
	}
}
