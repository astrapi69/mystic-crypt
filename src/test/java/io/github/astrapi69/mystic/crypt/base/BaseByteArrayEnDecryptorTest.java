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
package io.github.astrapi69.mystic.crypt.base;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.api.algorithm.AesAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.compound.CompoundAlgorithm;
import io.github.astrapi69.crypt.data.factory.SecretKeyFactoryExtensions;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.mystic.crypt.algorithm.MysticSymmetricAlgorithm;
import io.github.astrapi69.random.object.RandomStringFactory;

public class BaseByteArrayEnDecryptorTest
{

	CryptModel<Cipher, SecretKey, String> cryptModel;
	SecretKey secretKey;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@BeforeEach
	protected void setUp() throws Exception
	{
		secretKey = SecretKeyFactoryExtensions.newSecretKey(AesAlgorithm.AES.name(), 128);
		cryptModel = CryptModel.<Cipher, SecretKey, String> builder().key(secretKey)
			.algorithm(AesAlgorithm.AES).build();
	}

	/**
	 * Test method for {@link BaseByteArrayEncryptor#encrypt(byte[])}
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public void testDecrypt() throws Exception
	{
		// declare variables
		BaseByteArrayEncryptor encryptor;
		BaseByteArrayDecryptor decryptor;
		String plainMessage;
		plainMessage = RandomStringFactory.newRandomLongString(10000);

		encryptor = new BaseByteArrayEncryptor(cryptModel);
		decryptor = new BaseByteArrayDecryptor(cryptModel);
		byte[] plainMessageBytes = plainMessage.getBytes(StandardCharsets.UTF_8);
		byte[] encryptedBytes = encryptor.encrypt(plainMessageBytes);
		byte[] decrypt = decryptor.decrypt(encryptedBytes);
		String decryptedMessage = new String(decrypt, StandardCharsets.UTF_8);
		assertEquals(plainMessage, decryptedMessage);

	}

	/**
	 * Regression test proving GCM support: a caller who explicitly opts into
	 * {@link MysticSymmetricAlgorithm#AES_GCM_NO_PADDING} must be able to round-trip through
	 * {@link BaseByteArrayEncryptor}/{@link BaseByteArrayDecryptor}, and two encryptions of the
	 * same plaintext must produce different ciphertext (a fresh nonce per call). Before this fix,
	 * {@link BaseByteArrayDecryptor}'s construction-time cached cipher had no way to receive a
	 * per-message GCM nonce and threw immediately.
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public void testEncryptDecryptWithGcm() throws Exception
	{
		SecretKey gcmKey = SecretKeyFactoryExtensions.newSecretKey(AesAlgorithm.AES.name(), 128);
		CryptModel<Cipher, SecretKey, String> gcmModel = CryptModel
			.<Cipher, SecretKey, String> builder().key(gcmKey)
			.algorithm(MysticSymmetricAlgorithm.AES_GCM_NO_PADDING).build();

		BaseByteArrayEncryptor encryptor = new BaseByteArrayEncryptor(gcmModel);
		BaseByteArrayDecryptor decryptor = new BaseByteArrayDecryptor(gcmModel);
		byte[] plainMessageBytes = "the quick brown fox jumps over the lazy dog"
			.getBytes(StandardCharsets.UTF_8);

		byte[] firstEncrypted = encryptor.encrypt(plainMessageBytes);
		byte[] secondEncrypted = encryptor.encrypt(plainMessageBytes);
		assertFalse(Arrays.equals(firstEncrypted, secondEncrypted));

		assertEquals(new String(plainMessageBytes, StandardCharsets.UTF_8),
			new String(decryptor.decrypt(firstEncrypted), StandardCharsets.UTF_8));
		assertEquals(new String(plainMessageBytes, StandardCharsets.UTF_8),
			new String(decryptor.decrypt(secondEncrypted), StandardCharsets.UTF_8));
	}

	/**
	 * Test method proving ChaCha20-Poly1305 support: a caller who explicitly opts into
	 * {@link MysticSymmetricAlgorithm#CHACHA20_POLY1305} must be able to round-trip through
	 * {@link BaseByteArrayEncryptor}/{@link BaseByteArrayDecryptor}, and two encryptions of the
	 * same plaintext must produce different ciphertext (a fresh nonce per call). ChaCha20 keys must
	 * be exactly 32 bytes (256 bits), unlike AES which also accepts 128/192 bits.
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public void testEncryptDecryptWithChaCha20Poly1305() throws Exception
	{
		SecretKey chaChaKey = SecretKeyFactoryExtensions.newSecretKey(AesAlgorithm.AES.name(), 256);
		CryptModel<Cipher, SecretKey, String> chaChaModel = CryptModel
			.<Cipher, SecretKey, String> builder().key(chaChaKey)
			.algorithm(MysticSymmetricAlgorithm.CHACHA20_POLY1305).build();

		BaseByteArrayEncryptor encryptor = new BaseByteArrayEncryptor(chaChaModel);
		BaseByteArrayDecryptor decryptor = new BaseByteArrayDecryptor(chaChaModel);
		byte[] plainMessageBytes = "the quick brown fox jumps over the lazy dog"
			.getBytes(StandardCharsets.UTF_8);

		byte[] firstEncrypted = encryptor.encrypt(plainMessageBytes);
		byte[] secondEncrypted = encryptor.encrypt(plainMessageBytes);
		assertFalse(Arrays.equals(firstEncrypted, secondEncrypted));

		assertEquals(new String(plainMessageBytes, StandardCharsets.UTF_8),
			new String(decryptor.decrypt(firstEncrypted), StandardCharsets.UTF_8));
		assertEquals(new String(plainMessageBytes, StandardCharsets.UTF_8),
			new String(decryptor.decrypt(secondEncrypted), StandardCharsets.UTF_8));
	}

	/**
	 * Test method for {@link BaseByteArrayDecryptor#decrypt(byte[])}, encrypted data that is
	 * shorter than the nonce has to be rejected
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void testDecryptWithDataShorterThanTheNonce() throws Exception
	{
		SecretKey gcmKey = SecretKeyFactoryExtensions.newSecretKey(AesAlgorithm.AES.name(), 128);
		CryptModel<Cipher, SecretKey, String> gcmModel = CryptModel
			.<Cipher, SecretKey, String> builder().key(gcmKey)
			.algorithm(MysticSymmetricAlgorithm.AES_GCM_NO_PADDING).build();
		BaseByteArrayDecryptor decryptor = new BaseByteArrayDecryptor(gcmModel);

		assertThrows(IllegalArgumentException.class, () -> decryptor.decrypt(new byte[11]));
	}

	/**
	 * Test method for {@link BaseByteArrayDecryptor#decrypt(byte[])}, data of exactly the nonce
	 * length is <em>not</em> rejected by the length guard (it fails later during GCM decryption).
	 * This pins the boundary of the {@code length < NONCE_LENGTH} check so a {@code <=} mutant is
	 * caught.
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void testDecryptWithDataOfExactlyTheNonceLengthIsNotRejectedByTheLengthGuard()
		throws Exception
	{
		SecretKey gcmKey = SecretKeyFactoryExtensions.newSecretKey(AesAlgorithm.AES.name(), 128);
		CryptModel<Cipher, SecretKey, String> gcmModel = CryptModel
			.<Cipher, SecretKey, String> builder().key(gcmKey)
			.algorithm(MysticSymmetricAlgorithm.AES_GCM_NO_PADDING).build();
		BaseByteArrayDecryptor decryptor = new BaseByteArrayDecryptor(gcmModel);

		Exception exception = assertThrows(Exception.class, () -> decryptor.decrypt(new byte[12]));
		assertFalse(exception instanceof IllegalArgumentException,
			"data of exactly the nonce length must pass the length guard, not be rejected by it");
	}

	/**
	 * Test method for {@link BaseByteArrayEncryptor#BaseByteArrayEncryptor(SecretKey)} and
	 * {@link BaseByteArrayDecryptor#BaseByteArrayDecryptor(SecretKey)}, the constructors with the
	 * symmetric key only have to result in a working encryptor and decryptor pair
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void testEncryptDecryptWithSymmetricKeyOnlyConstructors() throws Exception
	{
		// the key-only constructors fall back to the default PBE algorithm, which rejects a plain
		// AES key, so both constructors must fail fast with an InvalidKeyException
		assertThrows(InvalidKeyException.class, () -> new BaseByteArrayEncryptor(secretKey));
		assertThrows(InvalidKeyException.class, () -> new BaseByteArrayDecryptor(secretKey));

		// a PBE key that carries its own salt and iteration count is accepted and round trips
		String algorithm = CompoundAlgorithm.PBE_WITH_SHA1_AND_128BIT_AES_CBC_BC.getAlgorithm();
		SecretKey pbeKey = SecretKeyFactory.getInstance(algorithm, "BC")
			.generateSecret(new PBEKeySpec("top secret".toCharArray(),
				new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }, 1000));
		BaseByteArrayEncryptor encryptor = new BaseByteArrayEncryptor(pbeKey);
		BaseByteArrayDecryptor decryptor = new BaseByteArrayDecryptor(pbeKey);
		byte[] plainMessageBytes = "the quick brown fox".getBytes(StandardCharsets.UTF_8);

		byte[] encrypted = encryptor.encrypt(plainMessageBytes);

		assertFalse(Arrays.equals(plainMessageBytes, encrypted));
		assertEquals("the quick brown fox",
			new String(decryptor.decrypt(encrypted), StandardCharsets.UTF_8));
	}
}
