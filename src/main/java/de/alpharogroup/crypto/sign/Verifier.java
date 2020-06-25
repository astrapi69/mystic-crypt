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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Objects;

/**
 * The class {@link Verifier} provides an algorithm for verifying byte arrays with given signed byte
 * arrays
 */
public final class Verifier
{

	/** The flag that indicates if the {@link Signature} object is initialized. */
	private boolean initialized;

	/** The {@link Signature} object for the verification */
	private final Signature signature;

	/** The {@link VerifyBean} object holds the model data for the verification */
	private final VerifyBean verifyBean;

	/**
	 * Instantiates a new {@link Verifier} object
	 *
	 * @param verifyBean
	 *            The {@link VerifyBean} object holds the model data for verifying
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the cipher object fails
	 */
	public Verifier(VerifyBean verifyBean) throws NoSuchAlgorithmException
	{

		Objects.requireNonNull(verifyBean);
		Objects.requireNonNull(verifyBean.getSignatureAlgorithm());
		if (verifyBean.getPublicKey() == null && verifyBean.getCertificate() == null)
		{
			throw new IllegalArgumentException("Please provide a public key or certificate");
		}
		this.verifyBean = verifyBean;
		this.signature = Signature.getInstance(this.verifyBean.getSignatureAlgorithm());
	}

	/**
	 * Initializes the {@link Signature} object for verifying
	 *
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 */
	private void initialize() throws InvalidKeyException
	{
		if (!initialized)
		{
			if (verifyBean.getPublicKey() != null)
			{
				signature.initVerify(this.verifyBean.getPublicKey());
				initialized = true;
				return;
			}
			if (verifyBean.getCertificate() != null)
			{
				signature.initVerify(this.verifyBean.getCertificate());
				initialized = true;
			}
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
	public synchronized boolean verify(byte[] bytesToVerify, byte[] signedBytes)
		throws InvalidKeyException, SignatureException
	{
		initialize();
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
	private synchronized boolean verifyWithCertificate(byte[] bytesToVerify, byte[] signedBytes)
		throws SignatureException, InvalidKeyException
	{
		signature.initVerify(verifyBean.getCertificate());
		signature.update(bytesToVerify);
		return signature.verify(signedBytes);
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
	private synchronized boolean verifyWithPublicKey(byte[] bytesToVerify, byte[] signedBytes)
		throws InvalidKeyException, SignatureException
	{
		signature.initVerify(verifyBean.getPublicKey());
		signature.update(bytesToVerify);
		return signature.verify(signedBytes);
	}

}
