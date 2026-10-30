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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.api.algorithm.AesAlgorithm;
import io.github.astrapi69.crypt.data.factory.SecretKeyFactoryExtensions;
import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.crypt.data.model.AesRsaCryptModel;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.mystic.crypt.io.FilteredDeserialization;
import io.github.astrapi69.random.object.RandomStringFactory;

/**
 * The unit test class for the class {@link PublicKeyEncryptor}
 */
public class PublicKeyEncryptorTest
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
		PublicKey publicKey;
		File publickeyDerDir;
		File publickeyDerFile;
		PublicKeyEncryptor encryptor;
		byte[] encrypted;
		String longString;

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		publickeyDerFile = new File(publickeyDerDir, "public.der");
		publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);
		encryptor = new PublicKeyEncryptor(publicKey);
		assertNotNull(encryptor);
		assertNotNull(encryptor);
		longString = RandomStringFactory.newRandomLongString(10000000);

		encrypted = encryptor.encrypt(longString.getBytes(StandardCharsets.UTF_8));
		assertNotNull(encrypted);
	}

	/**
	 * Test method for {@link PublicKeyEncryptor} constructor with {@link CryptModel} object
	 * 
	 * @throws Exception
	 *             is thrown if any error occurs
	 */
	@Test
	public void testConstructorWithCryptModel() throws Exception
	{
		PublicKeyEncryptor encryptor;

		PublicKey publicKey;
		SecretKey symmetricKey;
		CryptModel<Cipher, PublicKey, byte[]> encryptModel;
		CryptModel<Cipher, SecretKey, String> symmetricKeyModel;
		File publickeyDerDir;
		File publickeyDerFile;
		String longString;
		// new scenario...

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		publickeyDerFile = new File(publickeyDerDir, "public.der");
		publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);

		encryptModel = CryptModel.<Cipher, PublicKey, byte[]> builder().key(publicKey).build();
		symmetricKey = SecretKeyFactoryExtensions.newSecretKey(AesAlgorithm.AES.getAlgorithm(),
			128);
		symmetricKeyModel = CryptModel.<Cipher, SecretKey, String> builder().key(symmetricKey)
			.algorithm(AesAlgorithm.AES).operationMode(Cipher.ENCRYPT_MODE).build();

		encryptor = new PublicKeyEncryptor(encryptModel, symmetricKeyModel);
		assertNotNull(encryptor);
		longString = RandomStringFactory.newRandomLongString(10000000);

		byte[] encrypted = encryptor.encrypt(longString.getBytes(StandardCharsets.UTF_8));
		assertNotNull(encrypted);
	}

	/**
	 * Regression test proving the default symmetric transformation is no longer deterministic ECB:
	 * encrypting the same plaintext twice on the same {@link PublicKeyEncryptor} instance must
	 * produce different ciphertext each time (a fresh GCM nonce per call).
	 *
	 * @throws Exception
	 *             is thrown if any error occurs
	 */
	@Test
	public void testEncryptTwiceOnSameInstanceProducesDifferentCiphertext() throws Exception
	{
		File publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		File publickeyDerFile = new File(publickeyDerDir, "public.der");
		PublicKey publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);
		PublicKeyEncryptor encryptor = new PublicKeyEncryptor(publicKey);
		byte[] plaintext = "the quick brown fox jumps over the lazy dog"
			.getBytes(StandardCharsets.UTF_8);

		byte[] first = encryptor.encrypt(plaintext);
		byte[] second = encryptor.encrypt(plaintext);

		assertFalse(Arrays.equals(first, second));
	}

	/**
	 * The test above compares the whole outputs, and RSA-OAEP wraps the symmetric key differently
	 * every time, so two outputs differ whatever the GCM nonce is: with the nonce left all zeros it
	 * still passed (#227, the counter-run that replaced the random nonce by a zero array). One
	 * instance keeps one AES key for all its calls, so a repeated nonce is a repeated (key, nonce)
	 * pair, which in GCM gives the XOR of the plaintexts away. This test opens the envelope the way
	 * {@link PrivateKeyDecryptor} does and looks at the nonce and the ciphertext themselves.
	 *
	 * @throws Exception
	 *             is thrown if any error occurs
	 */
	@Test
	public void testEncryptTwiceOnSameInstanceUsesAFreshTwelveByteNonce() throws Exception
	{
		File publickeyDerFile = new File(new File(PathFinder.getSrcTestResourcesDir(), "der"),
			"public.der");
		PublicKeyEncryptor encryptor = new PublicKeyEncryptor(
			PublicKeyReader.readPublicKey(publickeyDerFile));
		byte[] plaintext = "the quick brown fox jumps over the lazy dog"
			.getBytes(StandardCharsets.UTF_8);

		byte[] first = symmetricPartOf(encryptor.encrypt(plaintext));
		byte[] second = symmetricPartOf(encryptor.encrypt(plaintext));

		assertEquals(12 + plaintext.length + 16, first.length,
			"a 12 byte nonce, the ciphertext as long as the plaintext, a 16 byte GCM tag");
		assertFalse(Arrays.equals(Arrays.copyOf(first, 12), Arrays.copyOf(second, 12)),
			"each call draws its own nonce under the same AES key");
		assertFalse(
			Arrays.equals(Arrays.copyOfRange(first, 12, first.length),
				Arrays.copyOfRange(second, 12, second.length)),
			"the same plaintext must not encrypt to the same ciphertext");
	}

	private static byte[] symmetricPartOf(final byte[] envelope) throws Exception
	{
		return FilteredDeserialization
			.deserialize(envelope, AesRsaCryptModel.class, PrivateKeyDecryptor.ENVELOPE)
			.getSymmetricKeyEncryptedObject();
	}
}
