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

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import io.github.astrapi69.crypt.data.factory.KeyPairGeneratorFactory;
import io.github.astrapi69.crypt.data.model.SharedSecretModel;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.Test;

import io.github.astrapi69.crypt.data.factory.KeyPairFactory;

public class SharedSecretEncryptorTest
{

	/**
	 * Test method for {@link PublicKeyEncryptor} constructor with {@link PublicKey} object
	 *
	 * @throws Exception
	 *             is thrown if any error occurs
	 */
	@Test
	public void testConstructorWithPublicKey() throws Exception
	{
		String actual;
		String expected;
		SharedSecretEncryptor encryptor;
		SharedSecretDecryptor decryptor;
		byte[] encrypted;
		byte[] decrypt;
		String longString;
		byte[] iv;
		SharedSecretModel aliceSharedSecretModel;
		SharedSecretModel bobSharedSecretModel;

		Security.addProvider(new BouncyCastleProvider());

		iv = new SecureRandom().generateSeed(16);

		KeyPair keyPairBob = KeyPairGeneratorFactory
			.newKeyPairGenerator("brainpoolp256r1", "ECDH", "BC").generateKeyPair();
		KeyPair keyPairAlice = KeyPairGeneratorFactory
			.newKeyPairGenerator("brainpoolp256r1", "ECDH", "BC").generateKeyPair();

		encryptor = new SharedSecretEncryptor(keyPairBob.getPrivate(), keyPairAlice.getPublic(),
			"ECDH", "AES", "BC", "AES/GCM/NoPadding", iv);

		expected = "Hi there, whats up!";

		encrypted = encryptor.encrypt(expected.getBytes(StandardCharsets.UTF_8));
		assertNotNull(encrypted);

		decryptor = new SharedSecretDecryptor(keyPairAlice.getPrivate(), keyPairBob.getPublic(),
			"ECDH", "AES", "BC", "AES/GCM/NoPadding", iv);

		decrypt = decryptor.decrypt(encrypted);
		actual = new String(decrypt, "UTF-8");

		assertEquals(expected, actual);

		// with model

		bobSharedSecretModel = SharedSecretModel.builder().privateKey(keyPairBob.getPrivate())
			.publicKey(keyPairAlice.getPublic()).keyAgreementAlgorithm("ECDH")
			.secretKeyAlgorithm("AES").provider("BC").cipherAlgorithm("AES/GCM/NoPadding").iv(iv)
			.build();


		encryptor = new SharedSecretEncryptor(bobSharedSecretModel);

		expected = "Hi there, whats up!";

		encrypted = encryptor.encrypt(expected.getBytes(StandardCharsets.UTF_8));
		assertNotNull(encrypted);

		aliceSharedSecretModel = SharedSecretModel.builder().privateKey(keyPairAlice.getPrivate())
			.publicKey(keyPairBob.getPublic()).keyAgreementAlgorithm("ECDH")
			.secretKeyAlgorithm("AES").provider("BC").cipherAlgorithm("AES/GCM/NoPadding").iv(iv)
			.build();

		decryptor = new SharedSecretDecryptor(aliceSharedSecretModel);

		decrypt = decryptor.decrypt(encrypted);
		actual = new String(decrypt, "UTF-8");

		assertEquals(expected, actual);
	}
}
