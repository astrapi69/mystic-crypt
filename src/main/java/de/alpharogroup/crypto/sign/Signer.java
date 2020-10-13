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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Objects;

/**
 * The class {@link Signer} provide sign algorithm for byte arrays
 */
public final class Signer
{

	/** The flag that indicates if the {@link Signature} object is initialized */
	private boolean initialized;

	/** The {@link Signature} object for signing */
	private final Signature signature;

	/** The {@link SignatureBean} object holds the model data for signing */
	private final SignatureBean signatureBean;

	/**
	 * Instantiates a new {@link Signer} object
	 *
	 * @param signatureBean
	 *            the signature bean
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 */
	public Signer(SignatureBean signatureBean) throws NoSuchAlgorithmException, InvalidKeyException
	{

		Objects.requireNonNull(signatureBean);
		Objects.requireNonNull(signatureBean.getPrivateKey());
		Objects.requireNonNull(signatureBean.getSignatureAlgorithm());
		this.signatureBean = signatureBean;
		this.signature = Signature.getInstance(this.signatureBean.getSignatureAlgorithm());
		initialize();
	}

	/**
	 * Initializes the {@link Signature} object for signing
	 *
	 * @throws InvalidKeyException
	 *             the invalid key exception
	 */
	private void initialize() throws InvalidKeyException
	{
		if (!initialized)
		{
			signature.initSign(this.signatureBean.getPrivateKey());
			initialized = true;
		}
	}

	/**
	 * Sign the given byte array with the given private key and the appropriate algorithms.
	 *
	 * @param bytesToSign
	 *            the bytes to sign
	 * @return the signed byte array
	 * @throws SignatureException
	 *             is thrown if the signature object is not initialized properly or if this
	 *             signature algorithm is unable to process the input data provided
	 */
	public synchronized byte[] sign(byte[] bytesToSign)
		throws SignatureException
	{
		signature.update(bytesToSign);
		return signature.sign();
	}

}
