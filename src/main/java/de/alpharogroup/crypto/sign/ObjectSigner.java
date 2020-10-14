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
import java.security.SignatureException;
import java.util.Base64;
import java.util.Objects;

/**
 * The class {@link ObjectSigner} provide sign algorithm for byte arrays
 */
public final class ObjectSigner<T extends Serializable>
{
	/* the signer for sign byte arrays. */
	private Signer signer;

	/**
	 * Instantiates a new {@link ObjectSigner} object
	 *
	 * @param signatureBean
	 *            the signature bean
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 */
	public ObjectSigner(SignatureBean signatureBean)
		throws NoSuchAlgorithmException, InvalidKeyException
	{
		this.signer = new Signer(signatureBean);
	}

	/**
	 * Sign the given byte array with the given private key and the appropriate algorithms.
	 *
	 * @param object
	 *            the object to sign
	 * @return the signed byte array
	 * @throws SignatureException
	 *             is thrown if the signature object is not initialized properly or if this
	 *             signature algorithm is unable to process the input data provided
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public synchronized String sign(final T object) throws SignatureException, IOException
	{
		byte[] signedBytes = this.signer.sign(toByteArray(object));
		String encoded = Base64.getEncoder().encodeToString(signedBytes);
		return encoded;
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
