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
package io.github.astrapi69.mystic.crypt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.api.algorithm.AesAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.MessageDigestAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.factory.SecretKeyFactoryExtensions;
import io.github.astrapi69.mystic.crypt.base.BaseByteArrayDecryptor;
import io.github.astrapi69.mystic.crypt.base.BaseByteArrayEncryptor;
import io.github.astrapi69.mystic.crypt.key.Ed25519Signer;
import io.github.astrapi69.mystic.crypt.key.Ed25519Verifier;
import io.github.astrapi69.mystic.crypt.key.MlKemKeyExchange;
import io.github.astrapi69.mystic.crypt.key.X25519KeyExchange;
import io.github.astrapi69.mystic.crypt.pw.PasswordEncryptor;
import io.github.astrapi69.mystic.crypt.sha.Sha3Hasher;

/**
 * Every code example shown in README.md, compiled and executed. If an example in the README is
 * changed, change it here too - a README snippet that does not run is worse than no snippet.
 */
class ReadmeExamplesTest
{

	/** README: "Encrypt and decrypt data" */
	@Test
	void symmetricEncryption() throws Exception
	{
		SecretKey key = SecretKeyFactoryExtensions.newSecretKey(AesAlgorithm.AES.getAlgorithm(),
			256);

		byte[] encrypted = new BaseByteArrayEncryptor(key)
			.encrypt("attack at dawn".getBytes(StandardCharsets.UTF_8));
		byte[] decrypted = new BaseByteArrayDecryptor(key).decrypt(encrypted);

		assertEquals("attack at dawn", new String(decrypted, StandardCharsets.UTF_8));
	}

	/** README: "Store a password" */
	@Test
	void passwordHashing()
	{
		PasswordEncryptor passwordEncryptor = PasswordEncryptor.getInstance();

		String stored = passwordEncryptor.hashPasswordArgon2id("correct horse battery staple");

		assertTrue(passwordEncryptor.matchArgon2id("correct horse battery staple", stored));
		assertFalse(passwordEncryptor.matchArgon2id("wrong password", stored));
	}

	/** README: "Sign and verify" */
	@Test
	void signAndVerify() throws Exception
	{
		KeyPair keyPair = Ed25519Signer.newKeyPair();
		byte[] document = "release 11.0.0".getBytes(StandardCharsets.UTF_8);

		byte[] signature = new Ed25519Signer(keyPair.getPrivate()).sign(document);

		assertTrue(new Ed25519Verifier(keyPair.getPublic()).verify(document, signature));
	}

	/** README: "Agree on a shared key" */
	@Test
	void keyAgreement() throws Exception
	{
		KeyPair alice = X25519KeyExchange.newKeyPair();
		KeyPair bob = X25519KeyExchange.newKeyPair();

		SecretKey aliceSecret = X25519KeyExchange.deriveSharedSecret(alice.getPrivate(),
			bob.getPublic(), 32);
		SecretKey bobSecret = X25519KeyExchange.deriveSharedSecret(bob.getPrivate(),
			alice.getPublic(), 32);

		assertArrayEquals(aliceSecret.getEncoded(), bobSecret.getEncoded());
	}

	/** README: "Post-quantum key encapsulation" */
	@Test
	void postQuantumKeyEncapsulation() throws Exception
	{
		KeyPair recipient = MlKemKeyExchange.newKeyPair(KeyPairGeneratorAlgorithm.ML_KEM_768);

		MlKemKeyExchange.Encapsulation sent = MlKemKeyExchange.encapsulate(recipient.getPublic(),
			KeyPairGeneratorAlgorithm.ML_KEM_768);
		SecretKey received = MlKemKeyExchange.decapsulate(recipient.getPrivate(),
			sent.getCiphertext(), KeyPairGeneratorAlgorithm.ML_KEM_768);

		assertArrayEquals(sent.getSharedSecret().getEncoded(), received.getEncoded());
	}

	/** README: "Hash" */
	@Test
	void hashing()
	{
		byte[] digest = Sha3Hasher.hashUtf8("hello", MessageDigestAlgorithm.SHA3_256);

		assertEquals(32, digest.length);
	}

}
