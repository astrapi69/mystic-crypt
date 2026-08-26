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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.AesAlgorithm;
import io.github.astrapi69.crypt.data.factory.SecretKeyFactoryExtensions;
import io.github.astrapi69.crypt.data.key.PrivateKeyExtensions;
import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.random.object.RandomStringFactory;

/**
 * The unit test class for the class {@link PrivateKeyDecryptor}
 */
public class PrivateKeyDecryptorTest
{

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeEach
	protected void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * One constructor-variant case: the round trip is identical, only how encryptor and decryptor
	 * are constructed (bare keys vs {@link CryptModel} objects) differs.
	 */
	record ConstructorCase(String description,
		ThrowingFunction<PublicKey, PublicKeyEncryptor> encryptorFactory,
		ThrowingFunction<PrivateKey, PrivateKeyDecryptor> decryptorFactory) {
	}

	static Stream<ConstructorCase> constructorCases()
	{
		return Stream.of(
			new ConstructorCase("bare key constructors", PublicKeyEncryptor::new,
				PrivateKeyDecryptor::new),
			new ConstructorCase("CryptModel constructors", publicKey -> {
				CryptModel<Cipher, PublicKey, byte[]> encryptModel = CryptModel
					.<Cipher, PublicKey, byte[]> builder().key(publicKey).build();
				SecretKey symmetricKey = SecretKeyFactoryExtensions
					.newSecretKey(AesAlgorithm.AES.getAlgorithm(), 128);
				CryptModel<Cipher, SecretKey, String> symmetricKeyModel = CryptModel
					.<Cipher, SecretKey, String> builder().key(symmetricKey)
					.algorithm(AesAlgorithm.AES).operationMode(Cipher.ENCRYPT_MODE).build();
				return new PublicKeyEncryptor(encryptModel, symmetricKeyModel);
			}, privateKey -> new PrivateKeyDecryptor(
				CryptModel.<Cipher, PrivateKey, byte[]> builder().key(privateKey).build(),
				AesAlgorithm.AES)));
	}

	/**
	 * Test method for the {@link PublicKeyEncryptor}/{@link PrivateKeyDecryptor} round trip over
	 * every constructor variant
	 *
	 * @param testCase
	 *            the constructor-variant case
	 * @throws Exception
	 *             is thrown if instantiation of the cipher object fails.
	 */
	@ParameterizedTest
	@MethodSource("constructorCases")
	public void testEncryptDecryptRoundTrip(ConstructorCase testCase) throws Exception
	{
		String plainText = RandomStringFactory.newRandomLongString(10000000);
		byte[] testBytes = plainText.getBytes("UTF-8");

		File derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		PrivateKey privateKey = PrivateKeyReader.readPrivateKey(new File(derDir, "private.der"));
		PublicKey publicKey = PrivateKeyExtensions.generatePublicKey(privateKey);

		PublicKeyEncryptor encryptor = testCase.encryptorFactory().apply(publicKey);
		assertNotNull(encryptor);
		byte[] encrypted = encryptor.encrypt(testBytes);

		PrivateKeyDecryptor decryptor = testCase.decryptorFactory().apply(privateKey);
		assertNotNull(decryptor);
		byte[] decrypted = decryptor.decrypt(encrypted);
		assertNotNull(decrypted);
		assertEquals(plainText, new String(decrypted, "UTF-8"), testCase.description());
	}

	/** A factory whose construction may throw - the cipher constructors declare exceptions. */
	@FunctionalInterface
	interface ThrowingFunction<T, R>
	{
		R apply(T input) throws Exception;
	}

	/**
	 * Test method for {@link PrivateKeyDecryptor#decrypt(byte[])}: a symmetric blob of exactly the
	 * nonce length is <em>not</em> rejected by the length guard (it fails later during GCM
	 * decryption). This pins the boundary of the {@code symmetricBlob.length < NONCE_LENGTH} check
	 * so a {@code <=} mutant is caught.
	 *
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@Test
	public void decrypt_withASymmetricBlobOfExactlyTheNonceLength_isNotRejectedByTheLengthGuard()
		throws Exception
	{
		File derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		File privatekeyDerFile = new File(derDir, "private.der");
		PrivateKey privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);
		PublicKey publicKey = PrivateKeyExtensions.generatePublicKey(privateKey);

		PublicKeyEncryptor encryptor = new PublicKeyEncryptor(publicKey);
		byte[] encrypted = encryptor.encrypt("payload".getBytes("UTF-8"));

		// keep the valid RSA-encrypted symmetric key but shrink the symmetric blob to exactly the
		// nonce length (12 bytes), leaving an empty ciphertext region
		io.github.astrapi69.crypt.data.model.AesRsaCryptModel model = org.apache.commons.lang3.SerializationUtils
			.deserialize(encrypted);
		io.github.astrapi69.crypt.data.model.AesRsaCryptModel tampered = new io.github.astrapi69.crypt.data.model.AesRsaCryptModel(
			model.getEncryptedKey(), new byte[12]);
		byte[] tamperedBytes = org.apache.commons.lang3.SerializationUtils.serialize(tampered);

		PrivateKeyDecryptor decryptor = new PrivateKeyDecryptor(privateKey);
		Exception exception = assertThrows(Exception.class, () -> decryptor.decrypt(tamperedBytes));
		assertFalse(exception instanceof IllegalArgumentException,
			"a blob of exactly the nonce length must pass the length guard, not be rejected by it");
	}

}
