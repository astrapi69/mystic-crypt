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
package io.github.astrapi69.mystic.crypt.core;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import org.apache.commons.lang3.ArrayUtils;

import io.github.astrapi69.check.Check;
import io.github.astrapi69.crypt.api.Cryptor;
import io.github.astrapi69.crypt.api.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.compound.CompoundAlgorithm;
import io.github.astrapi69.crypt.data.factory.AlgorithmParameterSpecFactory;
import io.github.astrapi69.crypt.data.factory.CipherFactory;
import io.github.astrapi69.crypt.data.factory.KeySpecFactory;
import io.github.astrapi69.crypt.data.factory.SecretKeyFactoryExtensions;
import io.github.astrapi69.crypt.data.model.CryptModel;

/**
 * The abstract class {@link AbstractCryptor} provides factory methods that may or must be
 * overwritten dependent of the specific implementor class.
 *
 * @param <C>
 *            the generic type of the cipher
 * @param <K>
 *            the generic type of the key
 * @param <T>
 *            the generic type of the decorator objects
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public abstract class AbstractCryptor<C, K, T> implements Serializable, Cryptor
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/** The crypto model. */
	protected final CryptModel<C, K, T> model;

	/**
	 * Constructor with the given {@link CryptModel}.
	 *
	 * @param model
	 *            The crypt model.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public AbstractCryptor(final CryptModel<C, K, T> model)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		Objects.requireNonNull(model);
		Check.get().notNull(model.getKey(), "model.getKey()");
		this.model = model;
		onInitialize();
	}

	/**
	 * Constructor with a key.
	 *
	 * @param key
	 *            The key.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	public AbstractCryptor(final K key)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		this(CryptModel.<C, K, T> builder().key(key).build());
	}

	/**
	 * Gets the current model
	 * 
	 * @return the model
	 */
	public CryptModel<C, K, T> getModel()
	{
		return this.model;
	}

	/**
	 * Factory method for creating a new algorithm that will be used with the cipher object.
	 * Overwrite this method to provide a specific algorithm.
	 *
	 * @return the new algorithm that will be used with the cipher object.
	 */
	protected String newAlgorithm()
	{
		if (model.getAlgorithm() == null)
		{
			return SunJCEAlgorithm.PBEWithMD5AndDES.getAlgorithm();
		}
		return model.getAlgorithm().getAlgorithm();
	}

	/**
	 * Factory method for creating a new {@link AlgorithmParameterSpec} from the given salt and
	 * iteration count. This method is invoked in the constructor from the derived classes and can
	 * be overridden so users can provide their own version of a new {@link AlgorithmParameterSpec}
	 * from the given salt and iteration count.
	 *
	 * @param salt
	 *            the salt
	 * @param iterationCount
	 *            the iteration count
	 * @return the new {@link AlgorithmParameterSpec} from the given salt and iteration count.
	 */
	protected AlgorithmParameterSpec newAlgorithmParameterSpec(final byte[] salt,
		final int iterationCount)
	{
		return AlgorithmParameterSpecFactory.newPBEParameterSpec(salt, iterationCount);
	}

	/**
	 * Factory method for creating a new {@link Cipher} from the given private key. This method is
	 * invoked in the constructor from the derived classes and can be overridden so users can
	 * provide their own version of a new {@link Cipher} from the given private key.
	 *
	 * @param key
	 *            the key
	 * @return the new {@link Cipher} from the given private key.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	protected C newCipher(final K key)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		return newCipher(key, newAlgorithm(), newSalt(), newIterationCount(), newOperationMode());
	}

	/**
	 * Factory method for creating a new {@link Cipher} from the given parameters. This method is
	 * invoked in the constructor from the derived classes and can be overridden so users can
	 * provide their own version of a new {@link Cipher} from the given parameters.
	 *
	 * @param key
	 *            the key
	 * @param algorithm
	 *            the algorithm
	 * @param salt
	 *            the salt.
	 * @param iterationCount
	 *            the iteration count
	 * @param operationMode
	 *            the operation mode for the new cipher object
	 * @return the cipher
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	protected abstract C newCipher(final K key, final String algorithm, final byte[] salt,
		final int iterationCount, final int operationMode)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException;

	/**
	 * Factory method for creating a new iteration count that will be used with the cipher object.
	 *
	 * @return the salt byte array
	 */
	protected int newIterationCount()
	{
		if (model.getIterationCount() == null)
		{
			return CompoundAlgorithm.ITERATIONCOUNT;
		}
		return model.getIterationCount();
	}

	/**
	 * Factory method for creating a new salt that will be used with the cipher object.
	 *
	 * @return the salt byte array
	 */
	protected byte[] newSalt()
	{
		if (ArrayUtils.isEmpty(getModel().getSalt()))
		{
			return CompoundAlgorithm.SALT;
		}
		return getModel().getSalt();
	}

	/**
	 * Factory method for creating a new {@link SecretKeyFactory} from the given algorithm. This
	 * method is invoked in the constructor from the derived classes and can be overridden so users
	 * can provide their own version of a new {@link SecretKeyFactory} from the given algorithm.
	 *
	 * @param algorithm
	 *            the algorithm
	 * @return the new {@link SecretKeyFactory} from the given algorithm.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 */
	protected SecretKeyFactory newSecretKeyFactory(final String algorithm)
		throws NoSuchAlgorithmException
	{
		return SecretKeyFactoryExtensions.newSecretKeyFactory(algorithm);
	}

	/**
	 * This method initialize the cipher object.
	 *
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	protected void onInitialize()
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		final C cipher = newCipher(model.getKey());
		model.setCipher(cipher);
		model.setInitialized(true);
	}


	/**
	 * Factory method for creating a new {@link KeySpec} from the given password. This method is
	 * invoked in the constructor from the derived classes and can be overridden so users can
	 * provide their own version of a new {@link KeySpec} from the given password
	 *
	 * @param password
	 *            the password
	 * @param salt
	 *            the salt
	 * @param iterationCount
	 *            the iteration count
	 * @return the new {@link KeySpec} from the given private key.
	 */
	protected KeySpec newKeySpec(final String password, final byte[] salt, final int iterationCount)
	{
		return KeySpecFactory.newPBEKeySpec(password, salt, iterationCount);
	}

	/**
	 * Factory method for creating a new {@link Cipher} from the given parameters. This method is
	 * invoked in the constructor from the derived classes and can be overridden so users can
	 * provide their own version of a new {@link Cipher} from the given parameters.
	 *
	 * @param operationMode
	 *            the operation mode
	 * @param key
	 *            the key
	 * @param paramSpec
	 *            the param spec
	 * @param alg
	 *            the alg
	 * @return the cipher
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 */
	protected Cipher newCipher(final int operationMode, final SecretKey key,
		final AlgorithmParameterSpec paramSpec, final String alg) throws NoSuchAlgorithmException,
		NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		return CipherFactory.newCipher(operationMode, key, paramSpec, alg);
	}

	/**
	 * Factory method for creating a new {@link Cipher} from the given parameters. This method is
	 * invoked in the constructor from the derived classes and can be overridden so users can
	 * provide their own version of a new {@link Cipher} from the given parameters.
	 *
	 * @param password
	 *            the password
	 * @param algorithm
	 *            the algorithm
	 * @param salt
	 *            the salt
	 * @param iterationCount
	 *            the iteration count
	 * @param operationMode
	 *            the operation mode for the new cipher object
	 * @return the cipher
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws UnsupportedEncodingException
	 *             is thrown if the named charset is not supported.
	 */
	protected Cipher newCipher(final String password, final String algorithm, final byte[] salt,
		final int iterationCount, final int operationMode)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		return CipherFactory.newCipher(password, algorithm, salt, iterationCount, operationMode);
	}
}
