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

import java.io.Serializable;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.apache.commons.lang3.SerializationUtils;

import io.github.astrapi69.crypto.model.CryptModel;
import io.github.astrapi69.throwable.RuntimeExceptionDecorator;

/**
 * The class {@link PublicKeyGenericEncryptor} can encrypt objects with his public key
 */
public class PublicKeyGenericEncryptor<T extends Serializable>
{
	/**
	 * The decorated encryptor object
	 */
	private final PublicKeyWithSymmetricKeyEncryptor encryptor;

	/**
	 * Instantiates a new {@link PublicKeyGenericEncryptor} with the given {@link CryptModel} for
	 * the public key and the given {@link CryptModel} for the symmetric key
	 *
	 * @param model
	 *            The crypt model
	 * @param symmetricKeyModel
	 *            The symmetric key model
	 */
	public PublicKeyGenericEncryptor(final CryptModel<Cipher, PublicKey, byte[]> model,
		final CryptModel<Cipher, SecretKey, String> symmetricKeyModel)
	{
		this(RuntimeExceptionDecorator
			.decorate(() -> new PublicKeyWithSymmetricKeyEncryptor(model, symmetricKeyModel)));
	}

	/**
	 * Instantiates a new {@link PublicKeyGenericEncryptor} with the given
	 * {@link PublicKeyWithSymmetricKeyEncryptor} object
	 *
	 * @param encryptor
	 *            The encryptor that will do the most work
	 */
	public PublicKeyGenericEncryptor(final PublicKeyWithSymmetricKeyEncryptor encryptor)
	{
		this.encryptor = encryptor;
	}

	/**
	 * Encrypt the given object
	 *
	 * @param toEncrypt
	 *            The object to encrypt
	 * @return The encrypted byte array from the given object to encrypt
	 * @throws Exception
	 *             is thrown if encryption fails
	 */
	public byte[] encrypt(final T toEncrypt) throws Exception
	{
		return encryptor.encrypt(SerializationUtils.serialize(toEncrypt));
	}
}
