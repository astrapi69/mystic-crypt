/**
 * Copyright (C) 2015 Asterios Raptis
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
