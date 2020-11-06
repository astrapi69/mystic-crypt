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
package de.alpharogroup.crypto.sign;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.util.Objects;

/**
 * The class {@link SignatureExtensions} can sign and verify byte arrays. For signing and verifying
 * the class {@link Signature} is used.
 */
public final class SignatureExtensions
{

	/**
	 * Sign the given byte array with the given private key and the appropriate algorithms
	 *
	 * @param privateKey
	 *            the private key
	 * @param signatureAlgorithm
	 *            the signature algorithm
	 * @param bytesToSign
	 *            the bytes to sign
	 * @return the signed byte array
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cipher object fails
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws SignatureException
	 *             is thrown if the signature object is not initialized properly or if this
	 *             signature algorithm is unable to process the input data provided
	 */
	public static byte[] sign(PrivateKey privateKey, String signatureAlgorithm, byte[] bytesToSign)
		throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
	{
		Signature signature = Signature.getInstance(signatureAlgorithm);
		signature.initSign(privateKey);
		signature.update(bytesToSign);
		return signature.sign();
	}

	/**
	 * Copies the given object to a byte array
	 *
	 * @param <T>
	 *            the generic type of the given object
	 * @param object
	 *            The object to copy
	 * @return the byte array
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static <T extends Serializable> byte[] toByteArray(final T object) throws IOException
	{
		Objects.requireNonNull(object);
		try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream))
		{
			objectOutputStream.writeObject(object);
			objectOutputStream.flush();
			return byteArrayOutputStream.toByteArray();
		}
	}

	/**
	 * Verify the given byte array with the given signed byte array with the given certificate and
	 * the appropriate algorithms
	 *
	 * @param certificate
	 *            the certificate
	 * @param signatureAlgorithm
	 *            the signature algorithm
	 * @param bytesToVerify
	 *            the bytes to verify
	 * @param signedBytes
	 *            the signed byte array
	 * @return true, if successful otherwise false
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cipher object fails
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws SignatureException
	 *             if the signature object is not initialized properly, the passed-in signature is
	 *             improperly encoded or of the wrong type, if this signature algorithm is unable to
	 *             process the input data provided, etc.
	 */
	public static boolean verify(Certificate certificate, String signatureAlgorithm,
		byte[] bytesToVerify, byte[] signedBytes)
		throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
	{
		Signature signature = Signature.getInstance(signatureAlgorithm);
		signature.initVerify(certificate);
		signature.update(bytesToVerify);
		return signature.verify(signedBytes);
	}

	/**
	 * Verify the given byte array with the given signed byte array with the given public key and
	 * the appropriate algorithms
	 *
	 * @param publicKey
	 *            the public key
	 * @param signatureAlgorithm
	 *            the signature algorithm
	 * @param bytesToVerify
	 *            the bytes to verify
	 * @param signedBytes
	 *            the signed byte array
	 * @return true, if successful otherwise false
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cipher object fails
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws SignatureException
	 *             if the signature object is not initialized properly, the passed-in signature is
	 *             improperly encoded or of the wrong type, if this signature algorithm is unable to
	 *             process the input data provided, etc.
	 */
	public static boolean verify(PublicKey publicKey, String signatureAlgorithm,
		byte[] bytesToVerify, byte[] signedBytes)
		throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
	{
		Signature signature = Signature.getInstance(signatureAlgorithm);
		signature.initVerify(publicKey);
		signature.update(bytesToVerify);
		return signature.verify(signedBytes);
	}

	private SignatureExtensions()
	{
	}
}
