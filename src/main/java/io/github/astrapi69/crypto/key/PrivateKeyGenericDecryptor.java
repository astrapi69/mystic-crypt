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
import java.security.PrivateKey;
import java.util.Objects;

import javax.crypto.Cipher;

import org.apache.commons.lang3.SerializationUtils;

import io.github.astrapi69.crypto.model.CryptModel;
import io.github.astrapi69.throwable.RuntimeExceptionDecorator;

/**
 * The class {@link PrivateKeyGenericDecryptor} decrypts encrypted objects the was encrypted with
 * the public key of the pendant private key of this class.
 */
public class PrivateKeyGenericDecryptor<T extends Serializable>
{
	/**
	 * The decorated decryptor object
	 */
	private final PrivateKeyDecryptor decryptor;

	/**
	 * Instantiates a new {@link PrivateKeyGenericDecryptor} with the given {@link CryptModel}
	 *
	 * @param model
	 *            The crypt model
	 */
	public PrivateKeyGenericDecryptor(final CryptModel<Cipher, PrivateKey, byte[]> model)
	{
		this(RuntimeExceptionDecorator.decorate(() -> new PrivateKeyDecryptor(model)));
	}

	/**
	 * Instantiates a new {@link PrivateKeyGenericDecryptor} with the given {@link PrivateKey}
	 *
	 * @param privateKey
	 *            The private key
	 */
	public PrivateKeyGenericDecryptor(final PrivateKey privateKey)
	{
		this(RuntimeExceptionDecorator.decorate(() -> new PrivateKeyDecryptor(privateKey)));
	}

	/**
	 * Instantiates a new {@link PrivateKeyGenericDecryptor} with the given
	 * {@link PrivateKeyDecryptor} object
	 *
	 * @param decryptor
	 *            The decryptor that will do the most work
	 */
	public PrivateKeyGenericDecryptor(final PrivateKeyDecryptor decryptor)
	{
		Objects.requireNonNull(decryptor);
		this.decryptor = decryptor;
	}

	/**
	 * Decrypt the given encrypted byte array and returns the generated object
	 *
	 * @param encrypted
	 *            The byte array to decrypt
	 * @return The decrypted object
	 * @throws Exception
	 *             is thrown if decryption fails
	 */
	public T decrypt(final byte[] encrypted) throws Exception
	{
		byte[] decrypt = this.decryptor.decrypt(encrypted);
		return SerializationUtils.deserialize(decrypt);
	}
}
