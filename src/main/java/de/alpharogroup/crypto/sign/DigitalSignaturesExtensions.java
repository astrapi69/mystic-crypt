/**
 * The MIT License
 * <p>
 * Copyright (C) 2015 Asterios Raptis
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto.sign;

import de.alpharogroup.crypto.factories.CipherFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Arrays;

/**
 * The class {@link DigitalSignaturesExtensions} can sign and verify byte arrays. For signing and verifying
 * the class {@link MessageDigest} is used.
 */
public final class DigitalSignaturesExtensions
{

	private DigitalSignaturesExtensions()
	{
	}

	/**
	 * Sign the given byte array with the given private key and the appropriate algorithms
	 *
	 * @param privateKey the private key
	 * @param messageDigestAlgorithm the message digest algorithm
	 * @param cipherAlgorithm the cipher algorithm
	 * @param bytesToSign the bytes to sign
	 * @return the signed byte array
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cypher object fails
	 * @throws BadPaddingException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails
	 * @throws IllegalBlockSizeException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails
	 */
	public static byte[] sign(PrivateKey privateKey, String messageDigestAlgorithm,
		String cipherAlgorithm, byte[] bytesToSign)
		throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
		BadPaddingException, IllegalBlockSizeException
	{
		MessageDigest messageDigest = MessageDigest.getInstance(messageDigestAlgorithm);
		byte[] hash = messageDigest.digest(bytesToSign);

		Cipher cipher = CipherFactory.newCipher(cipherAlgorithm);
		cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		return cipher.doFinal(hash);
	}

	private static byte[] decryptBytes(PublicKey publicKey, String cipherAlgorithm,
		byte[] encrpytedBytesToVerify)
		throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
		BadPaddingException, IllegalBlockSizeException
	{
		Cipher cipher = CipherFactory.newCipher(cipherAlgorithm);
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(encrpytedBytesToVerify);
	}

	private static byte[] decryptBytes(Certificate certificate, String cipherAlgorithm,
		byte[] encrpytedBytesToVerify)
		throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
		BadPaddingException, IllegalBlockSizeException
	{
		Cipher cipher = CipherFactory.newCipher(cipherAlgorithm);
		cipher.init(Cipher.DECRYPT_MODE, certificate);
		return cipher.doFinal(encrpytedBytesToVerify);
	}

	/**
	 * Verify the given byte array with the given signed byte array with the given public key and the appropriate algorithms
	 *
	 * @param publicKey the public key
	 * @param messageDigestAlgorithm the message digest algorithm
	 * @param cipherAlgorithm the cipher algorithm
	 * @param bytesToVerify the bytes to verify
	 * @param signedBytes the signed byte array
	 * @return true, if successful otherwise false
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws IllegalBlockSizeException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws BadPaddingException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 */
	public static boolean verify(PublicKey publicKey, String messageDigestAlgorithm,
		String cipherAlgorithm, byte[] bytesToVerify, byte[] signedBytes)
		throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
		BadPaddingException, NoSuchPaddingException
	{
		MessageDigest messageDigest = MessageDigest.getInstance(messageDigestAlgorithm);
		byte[] hash = messageDigest.digest(bytesToVerify);
		byte[] decryptedBytes = decryptBytes(publicKey, cipherAlgorithm, signedBytes);
		return Arrays.equals(hash, decryptedBytes);
	}

	/**
	 * Verify the given byte array with the given signed byte array with the given certificate and the appropriate algorithms
	 *
	 * @param certificate the certificate
	 * @param messageDigestAlgorithm the message digest algorithm
	 * @param cipherAlgorithm the cipher algorithm
	 * @param bytesToVerify the bytes to verify
	 * @param signedBytes the signed byte array
	 * @return true, if successful otherwise false
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cypher object fails.
	 * @throws IllegalBlockSizeException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cypher object fails.
	 * @throws BadPaddingException
	 *             is thrown if {@link Cipher#doFinal(byte[])} fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 */
	public static boolean verify(Certificate certificate, String messageDigestAlgorithm,
		String cipherAlgorithm, byte[] bytesToVerify, byte[] signedBytes)
		throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
		BadPaddingException, NoSuchPaddingException
	{
		MessageDigest messageDigest = MessageDigest.getInstance(messageDigestAlgorithm);
		byte[] hash = messageDigest.digest(bytesToVerify);
		byte[] decryptedBytes = decryptBytes(certificate, cipherAlgorithm, signedBytes);
		return Arrays.equals(hash, decryptedBytes);
	}

}
