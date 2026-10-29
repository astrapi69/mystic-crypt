/*
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

import java.io.ObjectInputFilter;
import java.io.Serializable;
import java.security.PrivateKey;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import javax.crypto.Cipher;

import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.mystic.crypt.io.FilteredDeserialization;
import io.github.astrapi69.throwable.RuntimeExceptionDecorator;

/**
 * The class {@link PrivateKeyGenericDecryptor} decrypts encrypted objects the was encrypted with
 * the public key of the pendant private key of this class.
 *
 * <p>
 * The decrypted bytes are read back through an allow-list: only the types given to the constructor
 * are built, {@link String} when none are given. Whoever wrote the encrypted bytes does not decide
 * which classes of the class path are instantiated.
 *
 * @param <T>
 *            the generic type of the decrypted object. It has to be {@link Serializable}, because
 *            the decrypted bytes are deserialized back into an object of this type
 */
public class PrivateKeyGenericDecryptor<T extends Serializable>
{
	/**
	 * The decorated decryptor object
	 */
	private final PrivateKeyDecryptor decryptor;

	/** The filter the decrypted object is read through */
	private final ObjectInputFilter payloadFilter;

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
		this(decryptor, List.of(String.class));
	}

	/**
	 * Instantiates a new {@link PrivateKeyGenericDecryptor} that reads back objects of the given
	 * types
	 *
	 * @param privateKey
	 *            The private key
	 * @param allowedTypes
	 *            every class the decrypted object is made of, the object's own class first
	 */
	public PrivateKeyGenericDecryptor(final PrivateKey privateKey,
		final Collection<Class<?>> allowedTypes)
	{
		this(RuntimeExceptionDecorator.decorate(() -> new PrivateKeyDecryptor(privateKey)),
			allowedTypes);
	}

	/**
	 * Instantiates a new {@link PrivateKeyGenericDecryptor} that reads back objects of the given
	 * types
	 *
	 * @param decryptor
	 *            The decryptor that will do the most work
	 * @param allowedTypes
	 *            every class the decrypted object is made of, the object's own class first
	 */
	public PrivateKeyGenericDecryptor(final PrivateKeyDecryptor decryptor,
		final Collection<Class<?>> allowedTypes)
	{
		Objects.requireNonNull(decryptor);
		this.decryptor = decryptor;
		this.payloadFilter = FilteredDeserialization.allowing(allowedTypes);
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
	@SuppressWarnings("unchecked")
	public T decrypt(final byte[] encrypted) throws Exception
	{
		byte[] decrypt = this.decryptor.decrypt(encrypted);
		return (T)FilteredDeserialization.deserialize(decrypt, Serializable.class, payloadFilter);
	}
}
