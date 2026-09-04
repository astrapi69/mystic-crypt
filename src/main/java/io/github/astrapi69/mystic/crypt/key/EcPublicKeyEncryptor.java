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

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;

import javax.crypto.Cipher;

/**
 * Encrypts bytes with an ec public key, through ECIES.
 * <p>
 * The counterpart of {@link PublicKeyEncryptor} for keys that have no direct encryption primitive
 * of their own. What this produces is opened by {@link EcPrivateKeyDecryptor} with the matching
 * private key and by nothing else.
 */
public final class EcPublicKeyEncryptor
{

	/** The public key that encrypts */
	private final PublicKey publicKey;

	/**
	 * Instantiates a new {@link EcPublicKeyEncryptor} with the given ec public key
	 *
	 * @param publicKey
	 *            the ec public key
	 * @throws IllegalArgumentException
	 *             if the given key is not an ec key
	 */
	public EcPublicKeyEncryptor(final PublicKey publicKey)
	{
		EcCipherSupport.requireEcKey(publicKey, ECPublicKey.class);
		this.publicKey = publicKey;
	}

	/**
	 * Encrypts the given bytes
	 *
	 * @param toEncrypt
	 *            the bytes to encrypt
	 * @return the encrypted bytes, which carry the ephemeral public value and the mac with them
	 * @throws Exception
	 *             if encryption fails
	 */
	public byte[] encrypt(final byte[] toEncrypt) throws Exception
	{
		return EcCipherSupport.newCipher(Cipher.ENCRYPT_MODE, publicKey).doFinal(toEncrypt);
	}
}
