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
package io.github.astrapi69.mystic.crypt.key;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import io.github.astrapi69.crypt.data.factory.KeyAgreementFactory;
import io.github.astrapi69.throwable.RuntimeExceptionDecorator;

public class SharedSecretDecryptor
{

	SecretKey secretKey;
	final String provider;
	final String cipherTransformation;
	IvParameterSpec ivSpec;

	public SharedSecretDecryptor(final PrivateKey privateKey, final PublicKey publicKey,
		final String algorithm, final String secretKeyAlgorithm, final String provider,
		final String cipherTransformation, final byte[] iv)
	{
		ivSpec = new IvParameterSpec(iv);
		this.provider = provider;
		this.cipherTransformation = cipherTransformation;
		secretKey = RuntimeExceptionDecorator.decorate(() -> KeyAgreementFactory
			.newSharedSecret(privateKey, publicKey, algorithm, secretKeyAlgorithm, provider));
	}

	public byte[] decrypt(final byte[] encrypted) throws Exception
	{
		Key secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), secretKey.getAlgorithm());
		Cipher cipher = Cipher.getInstance(cipherTransformation, provider);
		byte[] decryptedData;

		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
		decryptedData = new byte[cipher.getOutputSize(encrypted.length)];
		int decryptLength = cipher.update(encrypted, 0, encrypted.length, decryptedData, 0);
		cipher.doFinal(decryptedData, decryptLength);
		return decryptedData;
	}

}
