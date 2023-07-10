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

		bobSharedSecretModel = SharedSecretModel.builder()
			.privateKey(keyPairBob.getPrivate())
			.publicKey(keyPairAlice.getPublic())
			.keyAgreementAlgorithm("ECDH")
			.secretKeyAlgorithm("AES")
			.provider("BC")
			.cipherTransformation("AES/GCM/NoPadding")
			.iv(iv).build();


		encryptor = new SharedSecretEncryptor(bobSharedSecretModel);

		expected = "Hi there, whats up!";

		encrypted = encryptor.encrypt(expected.getBytes(StandardCharsets.UTF_8));
		assertNotNull(encrypted);

		aliceSharedSecretModel = SharedSecretModel.builder()
			.privateKey(keyPairAlice.getPrivate())
			.publicKey(keyPairBob.getPublic())
			.keyAgreementAlgorithm("ECDH")
			.secretKeyAlgorithm("AES")
			.provider("BC")
			.cipherTransformation("AES/GCM/NoPadding")
			.iv(iv).build();

		decryptor = new SharedSecretDecryptor(aliceSharedSecretModel);

		decrypt = decryptor.decrypt(encrypted);
		actual = new String(decrypt, "UTF-8");

		assertEquals(expected, actual);
	}
}
