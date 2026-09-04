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

import java.security.Key;
import java.util.Objects;

import javax.crypto.Cipher;

import io.github.astrapi69.crypt.api.provider.SecurityProvider;
import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * What the ECIES pair shares: the transformation, the cipher it builds, and the check that the key
 * offered is one the scheme can use.
 * <p>
 * An EC key has no direct encryption primitive the way an RSA key does. ECIES supplies one: a
 * shared secret is derived by ECDH against an ephemeral key pair generated for this message alone,
 * and the message is encrypted under that secret with a mac over the result. So every encryption
 * carries a fresh public value and no two are alike, and a changed byte is refused rather than
 * decrypted into rubbish.
 * <p>
 * {@code ECIESwithSHA256} is the transformation because it needs no parameter spec: the block
 * cipher variants require both sides to be handed the same nonce, which would have to travel beside
 * the ciphertext and would stop the output decrypting with nothing but the private key. Bouncy
 * Castle registers no AES-GCM variant of ECIES, so there is none to prefer.
 */
final class EcCipherSupport
{

	/**
	 * The ECIES transformation: a stream cipher keyed by the derived secret, with a SHA-256 based
	 * derivation and mac, and no parameter spec to carry.
	 */
	static final String TRANSFORMATION = "ECIESwithSHA256";

	private EcCipherSupport()
	{
	}

	/**
	 * Refuses a key the scheme cannot use, naming the algorithm it was given
	 *
	 * @param key
	 *            the key offered
	 * @param expected
	 *            the interface an ec key of this side implements
	 * @throws IllegalArgumentException
	 *             if the given key is not an ec key
	 */
	static void requireEcKey(final Key key, final Class<?> expected)
	{
		Objects.requireNonNull(key);
		if (!expected.isInstance(key))
		{
			throw new IllegalArgumentException("ECIES needs an ec key, but a '" + key.getAlgorithm()
				+ "' key was given. RSA has its own encryptor and decryptor; "
				+ "the key agreement curves X25519 and X448, the key encapsulation ML-KEM and the "
				+ "signature families ML-DSA and SLH-DSA have no encryption primitive at all");
		}
	}

	/**
	 * Builds the cipher for the given mode and key
	 *
	 * @param mode
	 *            {@link Cipher#ENCRYPT_MODE} or {@link Cipher#DECRYPT_MODE}
	 * @param key
	 *            the key to work with
	 * @return the initialised cipher
	 * @throws Exception
	 *             if the cipher cannot be built or initialised
	 */
	static Cipher newCipher(final int mode, final Key key) throws Exception
	{
		SecurityProviderSupport.ensureBouncyCastle();
		Cipher cipher = Cipher.getInstance(TRANSFORMATION, SecurityProvider.BC.name());
		cipher.init(mode, key);
		return cipher;
	}
}
