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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.mystic.crypt.key.HybridKemKeyExchange.HybridEncapsulation;
import io.github.astrapi69.mystic.crypt.key.HybridKemKeyExchange.HybridKeyPair;
import io.github.astrapi69.mystic.crypt.key.HybridKemKeyExchange.HybridPrivateKey;
import io.github.astrapi69.mystic.crypt.key.HybridKemKeyExchange.HybridPublicKey;

/**
 * The unit test class for the class {@link HybridKemKeyExchange}
 */
public class HybridKemKeyExchangeTest
{

	/**
	 * Test method for {@link HybridKemKeyExchange#newHybridKeyPair(KeyPairGeneratorAlgorithm)},
	 * {@link HybridKemKeyExchange#hybridEncapsulate(java.security.PublicKey, java.security.PublicKey, KeyPairGeneratorAlgorithm, int)}
	 * and
	 * {@link HybridKemKeyExchange#hybridDecapsulate(java.security.PrivateKey, java.security.PrivateKey, java.security.PublicKey, byte[], KeyPairGeneratorAlgorithm, int)}:
	 * the sender's encapsulated shared secret must match the recipient's decapsulated shared
	 * secret.
	 */
	@Test
	public void testEncapsulateAndDecapsulate() throws Exception
	{
		final HybridKeyPair recipientKeyPair = HybridKemKeyExchange
			.newHybridKeyPair(KeyPairGeneratorAlgorithm.ML_KEM_768);
		final HybridPublicKey recipientPublicKey = recipientKeyPair.getHybridPublicKey();
		final HybridPrivateKey recipientPrivateKey = recipientKeyPair.getHybridPrivateKey();

		final HybridEncapsulation encapsulation = HybridKemKeyExchange.hybridEncapsulate(
			recipientPublicKey.getX25519PublicKey(), recipientPublicKey.getMlKemPublicKey(),
			KeyPairGeneratorAlgorithm.ML_KEM_768, 32);
		assertNotNull(encapsulation.getSharedSecret());
		assertNotNull(encapsulation.getMlKemCiphertext());
		assertNotNull(encapsulation.getSenderX25519PublicKey());

		final SecretKey recovered = HybridKemKeyExchange.hybridDecapsulate(
			recipientPrivateKey.getX25519PrivateKey(), recipientPrivateKey.getMlKemPrivateKey(),
			encapsulation.getSenderX25519PublicKey(), encapsulation.getMlKemCiphertext(),
			KeyPairGeneratorAlgorithm.ML_KEM_768, 32);

		assertArrayEquals(encapsulation.getSharedSecret().getEncoded(), recovered.getEncoded());
		assertEquals(32, recovered.getEncoded().length);
	}

	/**
	 * Test method proving two independent encapsulations against the same recipient derive
	 * different shared secrets and ciphertexts (fresh ephemeral X25519 key and fresh ML-KEM
	 * randomness per call).
	 */
	@Test
	public void testEncapsulateIsNonDeterministic() throws Exception
	{
		final HybridKeyPair recipientKeyPair = HybridKemKeyExchange
			.newHybridKeyPair(KeyPairGeneratorAlgorithm.ML_KEM_768);
		final HybridPublicKey recipientPublicKey = recipientKeyPair.getHybridPublicKey();

		final HybridEncapsulation first = HybridKemKeyExchange.hybridEncapsulate(
			recipientPublicKey.getX25519PublicKey(), recipientPublicKey.getMlKemPublicKey(),
			KeyPairGeneratorAlgorithm.ML_KEM_768, 32);
		final HybridEncapsulation second = HybridKemKeyExchange.hybridEncapsulate(
			recipientPublicKey.getX25519PublicKey(), recipientPublicKey.getMlKemPublicKey(),
			KeyPairGeneratorAlgorithm.ML_KEM_768, 32);

		assertFalse(Arrays.equals(first.getSharedSecret().getEncoded(),
			second.getSharedSecret().getEncoded()));
		assertFalse(Arrays.equals(first.getMlKemCiphertext(), second.getMlKemCiphertext()));
	}

	/**
	 * Test method for {@link HybridKemKeyExchange#newHybridKeyPair(KeyPairGeneratorAlgorithm)} with
	 * a non-ML-KEM algorithm
	 */
	@Test
	public void testHybridKeyPairExposesItsParts() throws Exception
	{
		final HybridKeyPair keyPair = HybridKemKeyExchange
			.newHybridKeyPair(KeyPairGeneratorAlgorithm.ML_KEM_512);

		assertEquals(KeyPairGeneratorAlgorithm.ML_KEM_512, keyPair.getMlKemAlgorithm());
		assertEquals(KeyPairGeneratorAlgorithm.ML_KEM_512,
			keyPair.getHybridPublicKey().getMlKemAlgorithm());
		assertEquals(keyPair.getX25519KeyPair().getPublic(),
			keyPair.getHybridPublicKey().getX25519PublicKey());
		assertEquals(keyPair.getMlKemKeyPair().getPublic(),
			keyPair.getHybridPublicKey().getMlKemPublicKey());
		assertEquals(keyPair.getX25519KeyPair().getPrivate(),
			keyPair.getHybridPrivateKey().getX25519PrivateKey());
		assertEquals(keyPair.getMlKemKeyPair().getPrivate(),
			keyPair.getHybridPrivateKey().getMlKemPrivateKey());
	}

	/**
	 * Test method for {@link HybridKemKeyExchange#newHybridKeyPair(KeyPairGeneratorAlgorithm)}
	 */
	@Test
	public void testNewHybridKeyPairRejectsNonMlKemAlgorithm()
	{
		assertThrows(IllegalArgumentException.class,
			() -> HybridKemKeyExchange.newHybridKeyPair(KeyPairGeneratorAlgorithm.Ed25519));
	}

	/**
	 * Test method for
	 * {@link HybridKemKeyExchange#hybridEncapsulate(java.security.PublicKey, java.security.PublicKey, KeyPairGeneratorAlgorithm, int)}
	 * with a non-ML-KEM algorithm: the requireMlKem guard must reject it.
	 */
	@Test
	public void testHybridEncapsulateRejectsNonMlKemAlgorithm() throws Exception
	{
		final HybridKeyPair recipientKeyPair = HybridKemKeyExchange
			.newHybridKeyPair(KeyPairGeneratorAlgorithm.ML_KEM_768);
		final HybridPublicKey recipientPublicKey = recipientKeyPair.getHybridPublicKey();
		assertThrows(IllegalArgumentException.class,
			() -> HybridKemKeyExchange.hybridEncapsulate(recipientPublicKey.getX25519PublicKey(),
				recipientPublicKey.getMlKemPublicKey(), KeyPairGeneratorAlgorithm.Ed25519, 32));
	}

	/**
	 * Test method for
	 * {@link HybridKemKeyExchange#hybridDecapsulate(java.security.PrivateKey, java.security.PrivateKey, java.security.PublicKey, byte[], KeyPairGeneratorAlgorithm, int)}
	 * with a non-ML-KEM algorithm: the requireMlKem guard must reject it.
	 */
	@Test
	public void testHybridDecapsulateRejectsNonMlKemAlgorithm() throws Exception
	{
		final HybridKeyPair recipientKeyPair = HybridKemKeyExchange
			.newHybridKeyPair(KeyPairGeneratorAlgorithm.ML_KEM_768);
		final HybridPublicKey recipientPublicKey = recipientKeyPair.getHybridPublicKey();
		final HybridPrivateKey recipientPrivateKey = recipientKeyPair.getHybridPrivateKey();
		final HybridEncapsulation encapsulation = HybridKemKeyExchange.hybridEncapsulate(
			recipientPublicKey.getX25519PublicKey(), recipientPublicKey.getMlKemPublicKey(),
			KeyPairGeneratorAlgorithm.ML_KEM_768, 32);
		assertThrows(IllegalArgumentException.class,
			() -> HybridKemKeyExchange.hybridDecapsulate(recipientPrivateKey.getX25519PrivateKey(),
				recipientPrivateKey.getMlKemPrivateKey(), encapsulation.getSenderX25519PublicKey(),
				encapsulation.getMlKemCiphertext(), KeyPairGeneratorAlgorithm.Ed25519, 32));
	}

}
