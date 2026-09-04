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

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;

import javax.crypto.Cipher;

/**
 * Decrypts bytes that {@link EcPublicKeyEncryptor} encrypted with the matching ec public key.
 * <p>
 * The counterpart of {@link PrivateKeyDecryptor} for keys that have no direct encryption primitive
 * of their own. A foreign key or a changed byte is refused rather than answered with rubbish: the
 * scheme carries a mac over what it produced.
 */
public final class EcPrivateKeyDecryptor
{

	/** The private key that decrypts */
	private final PrivateKey privateKey;

	/**
	 * Instantiates a new {@link EcPrivateKeyDecryptor} with the given ec private key
	 *
	 * @param privateKey
	 *            the ec private key
	 * @throws IllegalArgumentException
	 *             if the given key is not an ec key
	 */
	public EcPrivateKeyDecryptor(final PrivateKey privateKey)
	{
		EcCipherSupport.requireEcKey(privateKey, ECPrivateKey.class);
		this.privateKey = privateKey;
	}

	/**
	 * Decrypts the given bytes
	 *
	 * @param encrypted
	 *            the encrypted bytes
	 * @return the decrypted bytes
	 * @throws Exception
	 *             if the bytes were not encrypted for this key, or were changed after encryption
	 */
	public byte[] decrypt(final byte[] encrypted) throws Exception
	{
		return EcCipherSupport.newCipher(Cipher.DECRYPT_MODE, privateKey).doFinal(encrypted);
	}
}
