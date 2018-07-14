/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto.factories;

import static org.testng.Assert.assertNotNull;

import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.provider.SecurityProvider;

/**
 * The class {@link CipherFactory}.
 */
public class CipherFactoryTest
{

	/**
	 * Test method for
	 * {@link CipherFactory#newCipher(int, SecretKey, AlgorithmParameterSpec, String)}.
	 */
	@Test
	public void testNewCipherIntSecretKeyAlgorithmParameterSpecString() throws Exception
	{
		final String algorithm = CryptConst.PBE_WITH_MD5_AND_DES;
		final KeySpec keySpec = KeySpecFactory.newPBEKeySpec(CryptConst.PRIVATE_KEY,
			CryptConst.SALT, CryptConst.ITERATIONCOUNT);
		final SecretKeyFactory factory = SecretKeyFactoryExtensions.newSecretKeyFactory(algorithm);
		final SecretKey key = factory.generateSecret(keySpec);

		final int operationMode = Cipher.ENCRYPT_MODE;
		final AlgorithmParameterSpec paramSpec = AlgorithmParameterSpecFactory
			.newPBEParameterSpec(CryptConst.SALT, CryptConst.ITERATIONCOUNT);
		Cipher cipher = CipherFactory.newCipher(operationMode, key, paramSpec, algorithm);
		assertNotNull(cipher);
	}

	/**
	 * Test method for {@link CipherFactory#newCipher(String)}.
	 */
	@Test
	public void testNewCipherString() throws Exception
	{
		final String algorithm = CryptConst.PBE_WITH_MD5_AND_DES;
		Cipher cipher = CipherFactory.newCipher(algorithm);
		assertNotNull(cipher);
	}

	/**
	 * Test method for {@link CipherFactory#newCipher(String, String)}.
	 */
	@Test
	public void testNewCipherStringString() throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		final String algorithm = "AES/CBC/PKCS5Padding";
		Cipher cipher = CipherFactory.newCipher(algorithm, SecurityProvider.BC.name());
		assertNotNull(cipher);
	}

	/**
	 * Test method for {@link CipherFactory#newCipher(String, String, byte[], int, int)}.
	 */
	@Test
	public void testNewCipherStringStringByteArrayIntInt() throws Exception
	{
		final String algorithm = CryptConst.PBE_WITH_MD5_AND_DES;

		final int operationMode = Cipher.ENCRYPT_MODE;

		Cipher cipher = CipherFactory.newCipher(CryptConst.PRIVATE_KEY, algorithm, CryptConst.SALT,
			CryptConst.ITERATIONCOUNT, operationMode);
		assertNotNull(cipher);
	}

}
