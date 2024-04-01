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

import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import io.github.astrapi69.crypt.data.model.CryptModel;

/**
 * The class {@link PublicKeyStringEncryptor} can encrypt strings with the given public key
 */
public class PublicKeyStringEncryptor extends PublicKeyGenericEncryptor<String>
{

	/**
	 * Instantiates a new {@link PublicKeyStringEncryptor} with the given {@link CryptModel} for the
	 * public key and the given {@link CryptModel} for the symmetric key
	 *
	 * @param model
	 *            The crypt model
	 * @param symmetricKeyModel
	 *            The symmetric key model
	 */
	public PublicKeyStringEncryptor(CryptModel<Cipher, PublicKey, byte[]> model,
		CryptModel<Cipher, SecretKey, String> symmetricKeyModel)
	{
		super(model, symmetricKeyModel);
	}

	/**
	 * Instantiates a new {@link PublicKeyStringEncryptor} with the given {@link PublicKey} object
	 *
	 * @param publicKey
	 *            the public key
	 */
	public PublicKeyStringEncryptor(PublicKey publicKey)
	{
		super(publicKey);
	}

	/**
	 * Instantiates a new {@link PublicKeyStringEncryptor} with the given {@link PublicKeyEncryptor}
	 * object
	 *
	 * @param encryptor
	 *            The encryptor that will do all the work
	 */
	public PublicKeyStringEncryptor(PublicKeyEncryptor encryptor)
	{
		super(encryptor);
	}

}
