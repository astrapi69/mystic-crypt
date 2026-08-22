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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

import org.junit.jupiter.api.Test;

/**
 * The unit test class for the classes {@link Ed25519Signer} and {@link Ed25519Verifier}
 */
public class Ed25519SignerVerifierTest
{

	/**
	 * Test method for {@link Ed25519Signer#sign(byte[])} and
	 * {@link Ed25519Verifier#verify(byte[], byte[])}
	 */
	@Test
	public void testSignAndVerify() throws Exception
	{
		KeyPair keyPair = Ed25519Signer.newKeyPair();
		Ed25519Signer signer = new Ed25519Signer(keyPair.getPrivate());
		Ed25519Verifier verifier = new Ed25519Verifier(keyPair.getPublic());
		byte[] data = "the quick brown fox jumps over the lazy dog"
			.getBytes(StandardCharsets.UTF_8);

		byte[] signature = signer.sign(data);
		assertNotNull(signature);

		assertTrue(verifier.verify(data, signature));
	}

	/**
	 * Test method for {@link Ed25519Verifier#verify(byte[], byte[])}
	 */
	@Test
	public void testVerifyFailsForTamperedData() throws Exception
	{
		KeyPair keyPair = Ed25519Signer.newKeyPair();
		Ed25519Signer signer = new Ed25519Signer(keyPair.getPrivate());
		Ed25519Verifier verifier = new Ed25519Verifier(keyPair.getPublic());
		byte[] data = "the quick brown fox jumps over the lazy dog"
			.getBytes(StandardCharsets.UTF_8);
		byte[] tampered = "the quick brown fox jumps over the lazy cat"
			.getBytes(StandardCharsets.UTF_8);

		byte[] signature = signer.sign(data);

		assertFalse(verifier.verify(tampered, signature));
	}

	/**
	 * Test method for {@link Ed25519Verifier#verify(byte[], byte[])}
	 *
	 * <p>
	 * A signature must not verify against a key pair it was not produced with.
	 */
	@Test
	public void testVerifyFailsForWrongKeyPair() throws Exception
	{
		KeyPair signingKeyPair = Ed25519Signer.newKeyPair();
		KeyPair otherKeyPair = Ed25519Signer.newKeyPair();
		Ed25519Signer signer = new Ed25519Signer(signingKeyPair.getPrivate());
		Ed25519Verifier verifier = new Ed25519Verifier(otherKeyPair.getPublic());
		byte[] data = "the quick brown fox jumps over the lazy dog"
			.getBytes(StandardCharsets.UTF_8);

		byte[] signature = signer.sign(data);

		assertFalse(verifier.verify(data, signature));
	}

}
