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
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Objects;

/**
 * The class {@link ObjectVerifier} provides an algorithm for verifying byte arrays with given signed byte
 * arrays
 */
public final class ObjectVerifier<T extends Serializable>
{

	/** The {@link Signature} object for the verification */
	private final Signature signature;

	/** The {@link VerifyBean} object holds the model data for the verification */
	private final VerifyBean verifyBean;

	/**
	 * Instantiates a new {@link ObjectVerifier} object
	 *
	 * @param verifyBean
	 *            The {@link VerifyBean} object holds the model data for verifying
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cipher object fails
	 */
	public ObjectVerifier(VerifyBean verifyBean) throws NoSuchAlgorithmException, InvalidKeyException
	{

		Objects.requireNonNull(verifyBean);
		Objects.requireNonNull(verifyBean.getSignatureAlgorithm());
		if (verifyBean.getPublicKey() == null && verifyBean.getCertificate() == null)
		{
			throw new IllegalArgumentException("Please provide a public key or certificate");
		}
		this.verifyBean = verifyBean;
		this.signature = Signature.getInstance(this.verifyBean.getSignatureAlgorithm());
		if (verifyBean.getPublicKey() != null)
		{
			signature.initVerify(this.verifyBean.getPublicKey());
		} else {
			signature.initVerify(this.verifyBean.getCertificate());
		}
	}

	/**
	 * Verify the given byte array with the given signed byte array
	 *
	 * @param bytesToVerify
	 *            the bytes to verify
	 * @param signedBytes
	 *            the signed byte array
	 * @return true, if successful otherwise false
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws SignatureException
	 *             if the signature object is not initialized properly, the passed-in signature is
	 *             improperly encoded or of the wrong type, if this signature algorithm is unable to
	 *             process the input data provided, etc.
	 */
	public synchronized boolean verify(T bytesToVerify, String signedBytes)
		throws InvalidKeyException, SignatureException, IOException
	{
		if (verifyBean.getPublicKey() != null)
		{
			return verifyWithPublicKey(bytesToVerify, signedBytes);
		}
		return verifyWithCertificate(bytesToVerify, signedBytes);
	}

	/**
	 * Verify the given byte array with the given signed byte array with the certificate of the
	 * verifyBean and the appropriate algorithms.
	 *
	 * @param bytesToVerify
	 *            the bytes to verify
	 * @param signedBytes
	 *            the signed byte array
	 * @return true, if successful otherwise false
	 * @throws SignatureException
	 *             if the signature object is not initialized properly, the passed-in signature is
	 *             improperly encoded or of the wrong type, if this signature algorithm is unable to
	 *             process the input data provided, etc.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 */
	private synchronized boolean verifyWithCertificate(T bytesToVerify, String signedBytes)
		throws SignatureException, InvalidKeyException, IOException
	{
		signature.initVerify(verifyBean.getCertificate());
		signature.update(toByteArray(bytesToVerify));
		byte[] signedBytesBytes = Base64.getDecoder().decode(signedBytes);
		return signature.verify(signedBytesBytes);
	}

	/**
	 * Verify the given byte array with the given signed byte array with the public key of the
	 * verifyBean and the appropriate algorithms.
	 *
	 * @param bytesToVerify
	 *            the bytes to verify
	 * @param signedBytes
	 *            the signed byte array
	 * @return true, if successful otherwise false
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws SignatureException
	 *             if the signature object is not initialized properly, the passed-in signature is
	 *             improperly encoded or of the wrong type, if this signature algorithm is unable to
	 *             process the input data provided, etc.
	 */
	private synchronized boolean verifyWithPublicKey(T bytesToVerify, String signedBytes)
		throws InvalidKeyException, SignatureException, IOException
	{
		signature.initVerify(verifyBean.getPublicKey());
		signature.update(toByteArray(bytesToVerify));
		byte[] signedBytesBytes = Base64.getDecoder().decode(signedBytes);
		return signature.verify(signedBytesBytes);
	}

	/**
	 * Copies the given object to a byte array
	 *
	 * @param object
	 *            The object to copy
	 * @return the byte array
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	private byte[] toByteArray(final T object) throws IOException
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
}
