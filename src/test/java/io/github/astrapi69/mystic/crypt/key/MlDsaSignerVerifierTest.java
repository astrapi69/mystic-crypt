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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;

/**
 * The unit test class for the classes {@link MlDsaSigner} and {@link MlDsaVerifier}
 */
public class MlDsaSignerVerifierTest
{

	@BeforeAll
	static void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Test method for {@link MlDsaSigner#sign(byte[])} and
	 * {@link MlDsaVerifier#verify(byte[], byte[])}
	 */
	@Test
	public void testSignAndVerify() throws Exception
	{
		final KeyPair keyPair = MlDsaSigner.newKeyPair(KeyPairGeneratorAlgorithm.ML_DSA_65);
		final MlDsaSigner signer = new MlDsaSigner(keyPair.getPrivate(),
			KeyPairGeneratorAlgorithm.ML_DSA_65);
		final MlDsaVerifier verifier = new MlDsaVerifier(keyPair.getPublic(),
			KeyPairGeneratorAlgorithm.ML_DSA_65);

		final byte[] data = "the quick brown fox jumps over the lazy dog"
			.getBytes(StandardCharsets.UTF_8);
		final byte[] signature = signer.sign(data);
		assertNotNull(signature);

		assertTrue(verifier.verify(data, signature));
	}

	/**
	 * Test method for {@link MlDsaVerifier#verify(byte[], byte[])} with tampered data
	 */
	@Test
	public void testVerifyFailsForTamperedData() throws Exception
	{
		final KeyPair keyPair = MlDsaSigner.newKeyPair(KeyPairGeneratorAlgorithm.ML_DSA_44);
		final MlDsaSigner signer = new MlDsaSigner(keyPair.getPrivate(),
			KeyPairGeneratorAlgorithm.ML_DSA_44);
		final MlDsaVerifier verifier = new MlDsaVerifier(keyPair.getPublic(),
			KeyPairGeneratorAlgorithm.ML_DSA_44);

		final byte[] data = "the quick brown fox".getBytes(StandardCharsets.UTF_8);
		final byte[] tampered = "the quick brown cat".getBytes(StandardCharsets.UTF_8);
		final byte[] signature = signer.sign(data);

		assertFalse(verifier.verify(tampered, signature));
	}

	/**
	 * Test method for {@link MlDsaSigner#newKeyPair(KeyPairGeneratorAlgorithm)} with a non-ML-DSA
	 * algorithm
	 */
	@Test
	public void testNewKeyPairRejectsNonMlDsaAlgorithm()
	{
		assertThrows(IllegalArgumentException.class,
			() -> MlDsaSigner.newKeyPair(KeyPairGeneratorAlgorithm.Ed25519));
	}

}
