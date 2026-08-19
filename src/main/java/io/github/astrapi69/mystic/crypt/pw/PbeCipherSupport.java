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
package io.github.astrapi69.mystic.crypt.pw;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.github.astrapi69.crypt.api.algorithm.compound.CompoundAlgorithm;
import io.github.astrapi69.crypt.data.factory.CipherFactory;
import io.github.astrapi69.random.number.RandomByteFactory;

/**
 * Package-private helper shared by the {@code pw} package's PBE-based encryptor/decryptor classes:
 * generates a fresh, random salt per call and builds a matching PBE {@link Cipher}, replacing the
 * fixed 8-byte {@link CompoundAlgorithm#SALT} and weak {@link CompoundAlgorithm#ITERATIONCOUNT}
 * these classes used to fall back to.
 */
final class PbeCipherSupport
{

	/**
	 * Salt length in bytes. Fixed at 8 bytes so a generated salt remains compatible with the legacy
	 * {@code PBEWithMD5AndDES} algorithm (the JDK's SunJCE provider rejects any salt for that
	 * algorithm that isn't exactly 8 bytes long).
	 */
	static final int SALT_LENGTH = 8;

	/** Default PBE iteration count, replacing the previous silent default of 19. */
	static final int ITERATION_COUNT = 65536;

	private static final String ALGORITHM = CompoundAlgorithm.PBE_WITH_SHA1_AND_128BIT_AES_CBC_BC
		.getAlgorithm();

	static
	{
		if (Security.getProvider("BC") == null)
		{
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private PbeCipherSupport()
	{
	}

	/**
	 * Generates a fresh, cryptographically random salt.
	 *
	 * @return the new salt byte array
	 */
	static byte[] newSalt()
	{
		return RandomByteFactory.randomByteArray(SALT_LENGTH);
	}

	/**
	 * Builds a new PBE {@link Cipher} for the given password, operation mode and salt.
	 *
	 * @param normalizedPassword
	 *            the NFC-normalized password
	 * @param operationMode
	 *            the operation mode
	 * @param salt
	 *            the salt
	 * @return the initialized cipher
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException
	 *             is thrown if generation of the SecretKey object fails.
	 * @throws NoSuchPaddingException
	 *             is thrown if instantiation of the cipher object fails.
	 * @throws InvalidKeyException
	 *             is thrown if initialization of the cipher object fails.
	 * @throws InvalidAlgorithmParameterException
	 *             is thrown if initialization of the cipher object fails.
	 */
	static Cipher newCipher(final String normalizedPassword, final int operationMode,
		final byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
	{
		return CipherFactory.newPBECipher(normalizedPassword.toCharArray(), operationMode,
			ALGORITHM, salt, ITERATION_COUNT);
	}

}
