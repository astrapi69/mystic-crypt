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
package de.alpharogroup.crypto.factories;

import java.io.File;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.algorithm.Algorithm;
import de.alpharogroup.crypto.key.KeySize;
import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.crypto.key.reader.PublicKeyReader;
import lombok.experimental.UtilityClass;

/**
 * The factory class {@link KeyPairFactory} holds methods for creating {@link KeyPair} objects.
 */
@UtilityClass
public class KeyPairFactory
{

	/**
	 * Factory method for creating a new {@link KeyPair} from the given algorithm and
	 * {@link KeySize}.
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param keySize
	 *            the key size as enum
	 * @return the new {@link KeyPair} from the given salt and iteration count.
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 */
	public static KeyPair newKeyPair(final Algorithm algorithm, final KeySize keySize)
		throws NoSuchAlgorithmException
	{
		return newKeyPair(algorithm.getAlgorithm(), keySize.getKeySize());
	}

	/**
	 * Factory method for creating a new {@link KeyPair} from the given algorithm and key size.
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param keySize
	 *            the key size
	 * @return the new {@link KeyPair} from the given salt and iteration count.
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 */
	public static KeyPair newKeyPair(final Algorithm algorithm, final int keySize)
		throws NoSuchAlgorithmException
	{
		return newKeyPair(algorithm.getAlgorithm(), keySize);
	}

	/**
	 * Factory method for creating a new {@link KeyPair} from the given parameters.
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param keySize
	 *            the key size
	 * @return the new {@link KeyPair} from the given parameters.
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 */
	public static KeyPair newKeyPair(final String algorithm, final int keySize)
		throws NoSuchAlgorithmException
	{
		final KeyPairGenerator generator = newKeyPairGenerator(algorithm, keySize);
		return generator.generateKeyPair();
	}

	/**
	 * Factory method for creating a new {@link KeyPair} from the given parameters.
	 *
	 * @param publicKey
	 *            the public key
	 * @param privateKey
	 *            the private key
	 * @return the new {@link KeyPair} from the given parameters.
	 */
	public static KeyPair newKeyPair(final PublicKey publicKey, final PrivateKey privateKey)
	{
		final KeyPair keyPair = new KeyPair(publicKey, privateKey);
		return keyPair;
	}

	/**
	 * Factory method for creating a new {@link KeyPair} from the given parameters.
	 *
	 * @param publicKeyDerFile
	 *            the public key der file
	 * @param privateKeyDerFile
	 *            the private key der file
	 * @return the new {@link KeyPair} from the given parameters. *
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchProviderException
	 *             is thrown if the specified provider is not registered in the security provider
	 *             list.
	 */
	public static KeyPair newKeyPair(final File publicKeyDerFile, final File privateKeyDerFile)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException,
		IOException
	{
		final PublicKey publicKey = PublicKeyReader.readPublicKey(publicKeyDerFile);
		final PrivateKey privateKey = PrivateKeyReader.readPrivateKey(privateKeyDerFile);
		return newKeyPair(publicKey, privateKey);
	}

	/**
	 * Factory method for creating a new {@link KeyPairGenerator} from the given parameters.
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param keySize
	 *            the key size
	 * @return the new {@link KeyPairGenerator} from the given parameters.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no Provider supports a KeyPairGeneratorSpi implementation for the
	 *             specified algorithm.
	 */
	public static KeyPairGenerator newKeyPairGenerator(final String algorithm, final int keySize)
		throws NoSuchAlgorithmException
	{
		final KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
		generator.initialize(keySize);
		return generator;
	}

	/**
	 * Factory method for creating a new {@link KeyPairGenerator} from the given parameters.
	 *
	 * @param algorithm
	 *            the algorithm
	 * @param keySize
	 *            the key size
	 * @param secureRandom
	 *            the secure random
	 * @return the new {@link KeyPairGenerator} from the given parameters.
	 * @throws NoSuchAlgorithmException
	 *             is thrown if no Provider supports a KeyPairGeneratorSpi implementation for the
	 *             specified algorithm.
	 */
	public static KeyPairGenerator newKeyPairGenerator(final String algorithm, final int keySize,
		final SecureRandom secureRandom) throws NoSuchAlgorithmException
	{
		final KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
		generator.initialize(keySize, secureRandom);
		return generator;
	}

	/**
	 * Factory method for creating a new {@link KeyPair} from the given parameters.
	 *
	 * @param publicKey
	 *            the public key
	 * @param privateKey
	 *            the private key
	 * @return the new {@link KeyPair} from the given parameters.
	 */
	public static KeyPair newKeyPair(final PublicKey publicKey, final PrivateKey privateKey,
		final String password) throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException,
		BadPaddingException, IllegalBlockSizeException, InvalidParameterSpecException, IOException,
		NoSuchProviderException
	{
		final byte[] encryptedPkcs8 = protectPrivateKeyWithPassword(privateKey, password);
		final PrivateKey privKey = PrivateKeyReader.readPrivateKey(encryptedPkcs8, "BC");

		final KeyPair keyPair = new KeyPair(publicKey, privKey);
		return keyPair;
	}

	/**
	 * Protect private key with password.
	 *
	 * @param privateKey
	 *            the private key
	 * @param password
	 *            the password
	 * @return the byte[]
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             the no such padding exception
	 * @throws InvalidKeyException
	 *             the invalid key exception
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws IllegalBlockSizeException
	 *             the illegal block size exception
	 * @throws BadPaddingException
	 *             the bad padding exception
	 * @throws InvalidParameterSpecException
	 *             the invalid parameter spec exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static byte[] protectPrivateKeyWithPassword(final PrivateKey privateKey,
		final String password) throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
		IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, IOException
	{
		final byte[] privateKeyEncoded = privateKey.getEncoded();

		final SecureRandom random = new SecureRandom();
		final byte[] salt = new byte[8];
		random.nextBytes(salt);

		final AlgorithmParameterSpec algorithmParameterSpec = AlgorithmParameterSpecFactory
			.newPBEParameterSpec(salt, 20);

		final SecretKey secretKey = SecretKeyFactoryExtensions.newSecretKey(password.toCharArray(),
			CryptConst.PBE_WITH_SHA1_AND_DES_EDE);

		final Cipher pbeCipher = Cipher.getInstance(CryptConst.PBE_WITH_SHA1_AND_DES_EDE);

		pbeCipher.init(Cipher.ENCRYPT_MODE, secretKey, algorithmParameterSpec);

		final byte[] ciphertext = pbeCipher.doFinal(privateKeyEncoded);

		final AlgorithmParameters algparms = AlgorithmParameters
			.getInstance(CryptConst.PBE_WITH_SHA1_AND_DES_EDE);
		algparms.init(algorithmParameterSpec);
		final EncryptedPrivateKeyInfo encinfo = new EncryptedPrivateKeyInfo(algparms, ciphertext);

		return encinfo.getEncoded();
	}
	
    /**
     * Decrypts the given byte array that represents a password protected private key.
     *
     * @param encryptedPrivateKeyBytes the byte array that represents a password protected private key
     * @param password the password
     * @param algorithm the algorithm
     * @return the private key
     * @throws IOException Signals that an I/O exception has occurred.
     * @throws NoSuchAlgorithmException is thrown if instantiation of the SecretKeyFactory object fails.
     * @throws NoSuchPaddingException the no such padding exception
     * @throws InvalidKeySpecException is thrown if generation of the SecretKey object fails.
     * @throws InvalidKeyException the invalid key exception
     * @throws InvalidAlgorithmParameterException is thrown if initialization of the cypher object fails.
     */
    public static PrivateKey decryptPasswordProtectedPrivateKey(byte[] encryptedPrivateKeyBytes, String password, String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException {
    	EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = new EncryptedPrivateKeyInfo(encryptedPrivateKeyBytes);
    	String algName = encryptedPrivateKeyInfo.getAlgName();
    	Cipher cipher = CipherFactory.newCipher(algName);
    	KeySpec pbeKeySpec = KeySpecFactory.newPBEKeySpec(password);    			
    	SecretKeyFactory secretKeyFactory = SecretKeyFactoryExtensions.newSecretKeyFactory(algName);
    	Key pbeKey = secretKeyFactory.generateSecret(pbeKeySpec);
    	AlgorithmParameters algParameters = encryptedPrivateKeyInfo.getAlgParameters();
    	cipher.init(Cipher.DECRYPT_MODE, pbeKey, algParameters);
    	KeySpec pkcs8KeySpec = encryptedPrivateKeyInfo.getKeySpec(cipher);
    	KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
    	return keyFactory.generatePrivate(pkcs8KeySpec);
    }


}
