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
package io.github.astrapi69.mystic.crypt.key;

import java.security.PrivateKey;

import javax.crypto.Cipher;

import io.github.astrapi69.crypt.data.model.CryptModel;

/**
 * The class {@link PrivateKeyStringDecryptor} decrypts encrypted strings the was encrypted with the
 * corresponding public key of the given private key
 */
public class PrivateKeyStringDecryptor extends PrivateKeyGenericDecryptor<String>
{

	/**
	 * Instantiates a new {@link PrivateKeyStringDecryptor} with the given {@link CryptModel}
	 *
	 * @param model
	 *            The crypt model
	 */
	public PrivateKeyStringDecryptor(CryptModel<Cipher, PrivateKey, byte[]> model)
	{
		super(model);
	}

	/**
	 * Instantiates a new {@link PrivateKeyStringDecryptor} with the given {@link PrivateKey}
	 *
	 * @param privateKey
	 *            The private key
	 */
	public PrivateKeyStringDecryptor(PrivateKey privateKey)
	{
		super(privateKey);
	}

	/**
	 * Instantiates a new {@link PrivateKeyGenericDecryptor} with the given
	 * {@link PrivateKeyDecryptor} object
	 *
	 * @param decryptor
	 *            The decryptor that will do the most work
	 */
	public PrivateKeyStringDecryptor(PrivateKeyDecryptor decryptor)
	{
		super(decryptor);
	}
}
