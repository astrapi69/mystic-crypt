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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPair;
import java.security.Security;

import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;

/**
 * The unit test class for the class {@link MlKemKeyExchange}
 */
public class MlKemKeyExchangeTest
{

	@BeforeAll
	static void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Test method for {@link MlKemKeyExchange#newKeyPair(KeyPairGeneratorAlgorithm)},
	 * {@link MlKemKeyExchange#encapsulate(java.security.PublicKey, KeyPairGeneratorAlgorithm)} and
	 * {@link MlKemKeyExchange#decapsulate(java.security.PrivateKey, byte[], KeyPairGeneratorAlgorithm)}
	 */
	@Test
	public void testEncapsulateAndDecapsulate() throws Exception
	{
		final KeyPair recipientKeyPair = MlKemKeyExchange
			.newKeyPair(KeyPairGeneratorAlgorithm.ML_KEM_768);

		final MlKemKeyExchange.Encapsulation encapsulation = MlKemKeyExchange
			.encapsulate(recipientKeyPair.getPublic(), KeyPairGeneratorAlgorithm.ML_KEM_768);
		assertNotNull(encapsulation.getSharedSecret());
		assertNotNull(encapsulation.getCiphertext());

		final SecretKey recovered = MlKemKeyExchange.decapsulate(recipientKeyPair.getPrivate(),
			encapsulation.getCiphertext(), KeyPairGeneratorAlgorithm.ML_KEM_768);

		assertArrayEquals(encapsulation.getSharedSecret().getEncoded(), recovered.getEncoded());
	}

	/**
	 * Test method for {@link MlKemKeyExchange#newKeyPair(KeyPairGeneratorAlgorithm)} with a
	 * non-ML-KEM algorithm
	 */
	@Test
	public void testNewKeyPairRejectsNonMlKemAlgorithm()
	{
		assertThrows(IllegalArgumentException.class,
			() -> MlKemKeyExchange.newKeyPair(KeyPairGeneratorAlgorithm.Ed25519));
	}

}
