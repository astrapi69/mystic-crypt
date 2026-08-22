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
 * The unit test class for the classes {@link SlhDsaSigner} and {@link SlhDsaVerifier}
 */
public class SlhDsaSignerVerifierTest
{

	@BeforeAll
	static void setUp()
	{
		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * Test method for {@link SlhDsaSigner#sign(byte[])} and
	 * {@link SlhDsaVerifier#verify(byte[], byte[])}
	 */
	@Test
	public void testSignAndVerify() throws Exception
	{
		final KeyPair keyPair = SlhDsaSigner
			.newKeyPair(KeyPairGeneratorAlgorithm.SLH_DSA_SHA2_128S);
		final SlhDsaSigner signer = new SlhDsaSigner(keyPair.getPrivate(),
			KeyPairGeneratorAlgorithm.SLH_DSA_SHA2_128S);
		final SlhDsaVerifier verifier = new SlhDsaVerifier(keyPair.getPublic(),
			KeyPairGeneratorAlgorithm.SLH_DSA_SHA2_128S);

		final byte[] data = "the quick brown fox jumps over the lazy dog"
			.getBytes(StandardCharsets.UTF_8);
		final byte[] signature = signer.sign(data);
		assertNotNull(signature);

		assertTrue(verifier.verify(data, signature));
	}

	/**
	 * Test method for {@link SlhDsaVerifier#verify(byte[], byte[])} with tampered data
	 */
	@Test
	public void testVerifyFailsForTamperedData() throws Exception
	{
		final KeyPair keyPair = SlhDsaSigner
			.newKeyPair(KeyPairGeneratorAlgorithm.SLH_DSA_SHAKE_128S);
		final SlhDsaSigner signer = new SlhDsaSigner(keyPair.getPrivate(),
			KeyPairGeneratorAlgorithm.SLH_DSA_SHAKE_128S);
		final SlhDsaVerifier verifier = new SlhDsaVerifier(keyPair.getPublic(),
			KeyPairGeneratorAlgorithm.SLH_DSA_SHAKE_128S);

		final byte[] data = "the quick brown fox".getBytes(StandardCharsets.UTF_8);
		final byte[] tampered = "the quick brown cat".getBytes(StandardCharsets.UTF_8);
		final byte[] signature = signer.sign(data);

		assertFalse(verifier.verify(tampered, signature));
	}

	/**
	 * Test method for {@link SlhDsaSigner#newKeyPair(KeyPairGeneratorAlgorithm)} with a non-SLH-DSA
	 * algorithm
	 */
	@Test
	public void testNewKeyPairRejectsNonSlhDsaAlgorithm()
	{
		assertThrows(IllegalArgumentException.class,
			() -> SlhDsaSigner.newKeyPair(KeyPairGeneratorAlgorithm.Ed25519));
	}

}
