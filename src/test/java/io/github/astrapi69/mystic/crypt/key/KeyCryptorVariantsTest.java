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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.apache.commons.lang3.SerializationUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.AesAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.Algorithm;
import io.github.astrapi69.crypt.api.algorithm.key.KeyPairWithModeAndPaddingAlgorithm;
import io.github.astrapi69.crypt.data.factory.SecretKeyFactoryExtensions;
import io.github.astrapi69.crypt.data.key.PrivateKeyExtensions;
import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypt.data.model.AesRsaCryptModel;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.mystic.crypt.algorithm.MysticSymmetricAlgorithm;

/**
 * The unit test class for the constructor variants and the symmetric transformation variants of the
 * public/private key based cryptors
 */
public class KeyCryptorVariantsTest
{

	private static final String PLAIN_TEXT = "the quick brown fox jumps over the lazy dog";

	private PrivateKey privateKey;

	private PublicKey publicKey;

	/**
	 * A scenario for a symmetric transformation used for the data leg of the hybrid encryption
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param symmetricAlgorithm
	 *            the symmetric transformation
	 */
	record SymmetricAlgorithmCase(String description, Algorithm symmetricAlgorithm) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static Stream<SymmetricAlgorithmCase> symmetricAlgorithmCases()
	{
		return Stream.of(
			new SymmetricAlgorithmCase("AES/GCM/NoPadding",
				MysticSymmetricAlgorithm.AES_GCM_NO_PADDING),
			new SymmetricAlgorithmCase("ChaCha20-Poly1305",
				MysticSymmetricAlgorithm.CHACHA20_POLY1305),
			new SymmetricAlgorithmCase("legacy bare AES", AesAlgorithm.AES));
	}

	@BeforeEach
	void setUp() throws Exception
	{
		File privatekeyDerFile = new File(PathFinder.getSrcTestResourcesDir(), "der/private.der");
		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);
		publicKey = PrivateKeyExtensions.generatePublicKey(privateKey);
	}

	private CryptModel<Cipher, PublicKey, byte[]> newPublicKeyModel()
	{
		return CryptModel.<Cipher, PublicKey, byte[]> builder().key(publicKey).build();
	}

	private CryptModel<Cipher, PrivateKey, byte[]> newPrivateKeyModel()
	{
		return CryptModel.<Cipher, PrivateKey, byte[]> builder().key(privateKey).build();
	}

	private static CryptModel<Cipher, SecretKey, String> newSymmetricKeyModel(
		final Algorithm symmetricAlgorithm) throws Exception
	{
		SecretKey symmetricKey = SecretKeyFactoryExtensions
			.newSecretKey(AesAlgorithm.AES.getAlgorithm(), 256);
		return CryptModel.<Cipher, SecretKey, String> builder().key(symmetricKey)
			.algorithm(symmetricAlgorithm).operationMode(Cipher.ENCRYPT_MODE).build();
	}

	/**
	 * Test method for {@link PublicKeyEncryptor} and {@link PrivateKeyDecryptor} with every
	 * supported symmetric transformation
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@ParameterizedTest
	@MethodSource("symmetricAlgorithmCases")
	public void encryptAndDecrypt_roundTripWithEverySymmetricTransformation(
		final SymmetricAlgorithmCase testCase) throws Exception
	{
		PublicKeyEncryptor encryptor = new PublicKeyEncryptor(newPublicKeyModel(),
			newSymmetricKeyModel(testCase.symmetricAlgorithm()));
		PrivateKeyDecryptor decryptor = new PrivateKeyDecryptor(newPrivateKeyModel(),
			testCase.symmetricAlgorithm());
		byte[] plainBytes = PLAIN_TEXT.getBytes(StandardCharsets.UTF_8);

		byte[] first = encryptor.encrypt(plainBytes);
		byte[] second = encryptor.encrypt(plainBytes);

		assertFalse(Arrays.equals(plainBytes, first));
		assertFalse(Arrays.equals(first, second), "a fresh nonce/key per call is expected");
		assertArrayEquals(plainBytes, decryptor.decrypt(first));
		assertArrayEquals(plainBytes, decryptor.decrypt(second));
	}

	/**
	 * Test method for {@link PublicKeyEncryptor} with an explicit asymmetric algorithm, the
	 * configured algorithm has to be kept and a decryptor with the same algorithm has to round trip
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void encryptAndDecrypt_withAnExplicitAsymmetricAlgorithm() throws Exception
	{
		CryptModel<Cipher, PublicKey, byte[]> publicKeyModel = CryptModel
			.<Cipher, PublicKey, byte[]> builder().key(publicKey)
			.algorithm(KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA256AndMGF1Padding)
			.build();
		CryptModel<Cipher, PrivateKey, byte[]> privateKeyModel = CryptModel
			.<Cipher, PrivateKey, byte[]> builder().key(privateKey)
			.algorithm(KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA256AndMGF1Padding)
			.build();
		PublicKeyEncryptor encryptor = new PublicKeyEncryptor(publicKeyModel,
			newSymmetricKeyModel(MysticSymmetricAlgorithm.AES_GCM_NO_PADDING));
		PrivateKeyDecryptor decryptor = new PrivateKeyDecryptor(privateKeyModel);

		assertEquals(KeyPairWithModeAndPaddingAlgorithm.RSA_ECB_OAEPWithSHA256AndMGF1Padding,
			encryptor.getModel().getAlgorithm());
		assertArrayEquals(PLAIN_TEXT.getBytes(StandardCharsets.UTF_8),
			decryptor.decrypt(encryptor.encrypt(PLAIN_TEXT.getBytes(StandardCharsets.UTF_8))));
	}

	/**
	 * Test method for {@link PrivateKeyDecryptor#decrypt(byte[])}, a symmetric blob that is too
	 * short to contain the nonce has to be rejected
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void decrypt_rejectsASymmetricBlobThatIsTooShortForTheNonce() throws Exception
	{
		PublicKeyEncryptor encryptor = new PublicKeyEncryptor(newPublicKeyModel(),
			newSymmetricKeyModel(MysticSymmetricAlgorithm.AES_GCM_NO_PADDING));
		PrivateKeyDecryptor decryptor = new PrivateKeyDecryptor(newPrivateKeyModel());
		AesRsaCryptModel cryptData = SerializationUtils
			.deserialize(encryptor.encrypt(PLAIN_TEXT.getBytes(StandardCharsets.UTF_8)));
		byte[] tooShort = SerializationUtils
			.serialize(AesRsaCryptModel.builder().encryptedKey(cryptData.getEncryptedKey())
				.symmetricKeyEncryptedObject(new byte[11]).build());

		assertThrows(IllegalArgumentException.class, () -> decryptor.decrypt(tooShort));
	}

	/**
	 * Test method for the model based constructors of {@link PublicKeyStringEncryptor} and
	 * {@link PrivateKeyStringDecryptor}
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void stringCryptors_withModels_roundTrip() throws Exception
	{
		PublicKeyStringEncryptor encryptor = new PublicKeyStringEncryptor(newPublicKeyModel(),
			newSymmetricKeyModel(MysticSymmetricAlgorithm.AES_GCM_NO_PADDING));
		PrivateKeyStringDecryptor decryptor = new PrivateKeyStringDecryptor(newPrivateKeyModel());

		assertEquals(PLAIN_TEXT, decryptor.decrypt(encryptor.encrypt(PLAIN_TEXT)));
	}

	/**
	 * Test method for the delegating constructor of {@link PublicKeyStringEncryptor}
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void stringEncryptor_withADelegateEncryptor_roundTrip() throws Exception
	{
		PublicKeyStringEncryptor encryptor = new PublicKeyStringEncryptor(new PublicKeyEncryptor(
			newPublicKeyModel(), newSymmetricKeyModel(MysticSymmetricAlgorithm.CHACHA20_POLY1305)));
		PrivateKeyStringDecryptor decryptor = new PrivateKeyStringDecryptor(new PrivateKeyDecryptor(
			newPrivateKeyModel(), MysticSymmetricAlgorithm.CHACHA20_POLY1305));

		assertEquals(PLAIN_TEXT, decryptor.decrypt(encryptor.encrypt(PLAIN_TEXT)));
	}

	/**
	 * Test method for the model based constructors of {@link PublicKeyGenericEncryptor} and
	 * {@link PrivateKeyGenericDecryptor}
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void genericCryptors_withModels_roundTrip() throws Exception
	{
		PublicKeyGenericEncryptor<String> encryptor = new PublicKeyGenericEncryptor<>(
			newPublicKeyModel(), newSymmetricKeyModel(MysticSymmetricAlgorithm.AES_GCM_NO_PADDING));
		PrivateKeyGenericDecryptor<String> decryptor = new PrivateKeyGenericDecryptor<>(
			newPrivateKeyModel());

		assertEquals(PLAIN_TEXT, decryptor.decrypt(encryptor.encrypt(PLAIN_TEXT)));
	}

	/**
	 * Test method for the private key constructor of {@link PrivateKeyHexStringDecryptor}, it has
	 * to decrypt the hex output of a {@link PublicKeyHexStringEncryptor} and must reject a missing
	 * key
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void hexStringDecryptor_withAPrivateKey_roundTrip() throws Exception
	{
		PublicKeyHexStringEncryptor encryptor = new PublicKeyHexStringEncryptor(publicKey);
		PrivateKeyHexStringDecryptor decryptor = new PrivateKeyHexStringDecryptor(privateKey);

		String encrypted = encryptor.encrypt(PLAIN_TEXT);

		assertEquals(PLAIN_TEXT, decryptor.decrypt(encrypted));
		assertThrows(NullPointerException.class, () -> new PrivateKeyHexStringDecryptor(null));
	}
}
