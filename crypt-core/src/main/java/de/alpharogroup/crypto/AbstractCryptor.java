package de.alpharogroup.crypto;

import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEParameterSpec;

import de.alpharogroup.check.Check;
import de.alpharogroup.crypto.factories.KeySpecFactory;
import lombok.AccessLevel;
import lombok.Getter;

/**
 * A base cryptor implementation.
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public abstract class AbstractCryptor implements Serializable
{

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/**
	 * The Cipher object.
	 */
	protected final Cipher cipher;

	/**
	 * The private key.
	 */
	@Getter
	private final String privateKey;

	/**
	 * The flag initialized that indicates if the cypher is initialized for decryption.
	 *
	 * @return true, if is initialized
	 */
	@Getter(value = AccessLevel.PRIVATE)
	private final boolean initialized;

	/**
	 * Constructor with a private key.
	 *
	 * @param privateKey
	 *            The private key.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cypher object fails.
	 */
	public AbstractCryptor(final String privateKey)
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException
	{
		Check.get().notEmpty(privateKey, "privateKey");
		this.privateKey = privateKey;
		this.cipher = newCipher(privateKey);
		initialized = true;
	}


	/**
	 * Factory method for creating a new {@link Cipher} from the given private key. This method is
	 * invoked in the constructor from the derived classes and can be overridden so users can
	 * provide their own version of a new {@link Cipher} from the given private key.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the new {@link Cipher} from the given private key.
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 */
	protected Cipher newCipher(final String privateKey)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException
		{
			return newCipher(privateKey, CryptConst.PBEWITH_MD5AND_DES, CryptConst.SALT, CryptConst.ITERATIONCOUNT, getOperationMode());
		}

	/**
	 * Abstact callback method for get the operation mode.
	 * the operation mode can be one of the following values: ENCRYPT_MODE, DECRYPT_MODE, WRAP_MODE or UNWRAP_MODE
	 *
	 * @return the operation mode
	 */
	protected abstract int getOperationMode();


	/**
	 * Factory method for creating a new {@link Cipher} from the given private key. This method is
	 * invoked in the constructor from the derived classes and can be overridden so users can
	 * provide their own version of a new {@link Cipher} from the given private key.
	 *
	 * @param privateKey
	 *            the private key
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
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 */
	protected Cipher newCipher(final String privateKey, final String algorithm, final byte[] salt,
		final int iterationCount, final int operationMode)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
		InvalidKeyException, InvalidAlgorithmParameterException
	{
		final KeySpec keySpec = newKeySpec(privateKey, salt, iterationCount);
		final SecretKeyFactory factory = newSecretKeyFactory(algorithm);
		final SecretKey key = factory.generateSecret(keySpec);
		final AlgorithmParameterSpec paramSpec = newAlgorithmParameterSpec(salt, iterationCount);
		final String alg = key.getAlgorithm();
		final Cipher cipher = Cipher.getInstance(alg);
		cipher.init(operationMode, key, paramSpec);
		return cipher;
	}

	/**
	 * Factory method for creating a new {@link AlgorithmParameterSpec} from the given salt and iteration count. This method is
	 * invoked in the constructor from the derived classes and can be overridden so users can
	 * provide their own version of a new {@link AlgorithmParameterSpec} from the given salt and iteration count.
	 *
	 * @param salt the salt
	 * @param iterationCount the iteration count
	 * @return the new {@link AlgorithmParameterSpec} from the given salt and iteration count.
	 */
	protected AlgorithmParameterSpec newAlgorithmParameterSpec(final byte[] salt,final int iterationCount){
		final AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);
		return paramSpec;
	}

	/**
	 * Factory method for creating a new {@link KeySpec} from the given private key. This method is
	 * invoked in the constructor from the derived classes and can be overridden so users can
	 * provide their own version of a new {@link KeySpec} from the given private key.
	 *
	 * @param privateKey
	 *            the private key
	 * @return the new {@link KeySpec} from the given private key.
	 */
	protected KeySpec newKeySpec(final String privateKey, final byte[] salt,final int iterationCount)
	{
		return KeySpecFactory.newPBEKeySpec(privateKey, salt, iterationCount);
	}

	/**
	 * Factory method for creating a new {@link SecretKeyFactory} from the given algorithm. This method is
	 * invoked in the constructor from the derived classes and can be overridden so users can
	 * provide their own version of a new {@link SecretKeyFactory} from the given algorithm.
	 *
	 * @param algorithm
	 *            the algorithm
	 * @return the new {@link SecretKeyFactory} from the given algorithm.
	 */
	protected SecretKeyFactory newSecretKeyFactory(final String algorithm) throws NoSuchAlgorithmException {
		final SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
		return factory;
	}

}
