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
package io.github.astrapi69.mystic.crypt.srp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link SRP6aClient} and {@link SRP6aServer}.
 */
class SRP6aProtocolTest
{

	@Test
	void testSuccessfulAuthentication()
	{
		final String identity = "testuser";
		final char[] password = "testPassword123".toCharArray();

		final SRP6aVerifierGenerator generator = new SRP6aVerifierGenerator();
		final byte[] salt = generator.generateSalt();
		final BigInteger verifier = generator.generateVerifier(identity, password.clone(), salt);

		final SRP6aServer server = new SRP6aServer();
		server.setVerifier(verifier);

		final SRP6aClient client = new SRP6aClient();

		final BigInteger clientPublicKey = client.generatePublicValue();
		final BigInteger serverPublicKey = server.generatePublicValue();

		client.setServerCredentials(salt, serverPublicKey);
		server.setClientPublicKey(clientPublicKey);

		final BigInteger clientSessionKey = client.computeSessionKey(identity, password.clone());
		final BigInteger serverSessionKey = server.computeSessionKey();

		assertEquals(clientSessionKey, serverSessionKey, "Session keys should match");

		final BigInteger clientProof = client.computeProof(clientSessionKey);
		assertTrue(server.verifyClientProof(clientProof, serverSessionKey));

		final BigInteger serverProof = server.computeServerProof(clientProof, serverSessionKey);
		assertTrue(client.verifyServerProof(serverProof, clientSessionKey));
	}

	@Test
	void testFailedAuthenticationWithWrongPassword()
	{
		final String identity = "testuser";
		final char[] correctPassword = "correctPassword".toCharArray();
		final char[] wrongPassword = "wrongPassword".toCharArray();

		final SRP6aVerifierGenerator generator = new SRP6aVerifierGenerator();
		final byte[] salt = generator.generateSalt();
		final BigInteger verifier = generator.generateVerifier(identity, correctPassword.clone(),
			salt);

		final SRP6aServer server = new SRP6aServer();
		server.setVerifier(verifier);

		final SRP6aClient client = new SRP6aClient();

		final BigInteger clientPublicKey = client.generatePublicValue();
		final BigInteger serverPublicKey = server.generatePublicValue();

		client.setServerCredentials(salt, serverPublicKey);
		server.setClientPublicKey(clientPublicKey);

		final BigInteger clientSessionKey = client.computeSessionKey(identity,
			wrongPassword.clone());
		final BigInteger serverSessionKey = server.computeSessionKey();

		assertFalse(clientSessionKey.equals(serverSessionKey),
			"Session keys should not match with wrong password");

		final BigInteger clientProof = client.computeProof(clientSessionKey);
		assertFalse(server.verifyClientProof(clientProof, serverSessionKey));
	}

	@Test
	void testClientConstructorWithDefaults()
	{
		final SRP6aClient client = new SRP6aClient();

		assertNotNull(client);
		client.generatePublicValue();
		assertNotNull(client.getPublicValue());
	}

	@Test
	void testClientConstructorWithCustomParameters()
	{
		final BigInteger customN = new BigInteger(
			"1000000000000000000000000000000000000000000000000000000000000000");
		final BigInteger customG = BigInteger.valueOf(3);

		final SRP6aClient client = new SRP6aClient(customN, customG, "SHA-512");

		assertNotNull(client);
	}

	@Test
	void testServerConstructorWithDefaults()
	{
		final SRP6aServer server = new SRP6aServer();

		assertNotNull(server);
	}

	@Test
	void testServerGeneratePublicValueWithoutVerifier()
	{
		final SRP6aServer server = new SRP6aServer();

		assertThrows(IllegalStateException.class, () -> {
			server.generatePublicValue();
		});
	}

	@Test
	void testClientSetServerCredentialsWithNullSalt()
	{
		final SRP6aClient client = new SRP6aClient();

		assertThrows(IllegalArgumentException.class, () -> {
			client.setServerCredentials(null, BigInteger.TEN);
		});
	}

	@Test
	void testClientSetServerCredentialsWithNullPublicKey()
	{
		final SRP6aClient client = new SRP6aClient();
		final byte[] salt = new byte[16];

		assertThrows(IllegalArgumentException.class, () -> {
			client.setServerCredentials(salt, null);
		});
	}

	@Test
	void testServerSetClientPublicKeyWithNull()
	{
		final SRP6aServer server = new SRP6aServer();

		assertThrows(IllegalArgumentException.class, () -> {
			server.setClientPublicKey(null);
		});
	}

	@Test
	void testClientComputeSessionKeyWithoutCredentials()
	{
		final SRP6aClient client = new SRP6aClient();
		client.generatePublicValue();

		assertThrows(IllegalArgumentException.class, () -> {
			client.computeSessionKey("user", "password".toCharArray());
		});
	}

	@Test
	void testServerComputeSessionKeyWithoutClientPublicKey()
	{
		final SRP6aVerifierGenerator generator = new SRP6aVerifierGenerator();
		final byte[] salt = generator.generateSalt();
		final BigInteger verifier = generator.generateVerifier("user", "password".toCharArray(),
			salt);

		final SRP6aServer server = new SRP6aServer();
		server.setVerifier(verifier);
		server.generatePublicValue();

		assertThrows(IllegalStateException.class, () -> {
			server.computeSessionKey();
		});
	}

	@Test
	void testVerifyClientProofWithNullProof()
	{
		final SRP6aServer server = new SRP6aServer();

		assertFalse(server.verifyClientProof(null, BigInteger.TEN));
	}

	@Test
	void testVerifyServerProofWithNullProof()
	{
		final SRP6aClient client = new SRP6aClient();

		assertFalse(client.verifyServerProof(null, BigInteger.TEN));
	}

	@Test
	void testServerRejectsZeroClientPublicKey()
	{
		final SRP6aVerifierGenerator generator = new SRP6aVerifierGenerator();
		final byte[] salt = generator.generateSalt();
		final BigInteger verifier = generator.generateVerifier("testuser",
			"testPassword123".toCharArray(), salt);

		final SRP6aServer server = new SRP6aServer();
		server.setVerifier(verifier);
		server.generatePublicValue();

		// The classic SRP zero-key attack: a malicious client sends A = 0 (or any multiple of N)
		// to try to force a session key that does not depend on the verifier/password at all.
		assertThrows(SecurityException.class, () -> server.setClientPublicKey(BigInteger.ZERO));
		assertThrows(SecurityException.class,
			() -> server.setClientPublicKey(SRP6aVerifierGenerator.DEFAULT_N));
	}

	@Test
	void testClientRejectsZeroServerPublicKey()
	{
		final SRP6aClient client = new SRP6aClient();
		client.generatePublicValue();
		final byte[] salt = new byte[16];

		// Same attack, mirrored: a malicious/compromised server sends B = 0
		assertThrows(SecurityException.class,
			() -> client.setServerCredentials(salt, BigInteger.ZERO));
		assertThrows(SecurityException.class,
			() -> client.setServerCredentials(salt, SRP6aVerifierGenerator.DEFAULT_N));
	}

	@Test
	void testMultipleAuthenticationRounds()
	{
		final String identity = "testuser";
		final char[] password = "testPassword123".toCharArray();

		final SRP6aVerifierGenerator generator = new SRP6aVerifierGenerator();
		final byte[] salt = generator.generateSalt();
		final BigInteger verifier = generator.generateVerifier(identity, password.clone(), salt);

		for (int i = 0; i < 3; i++)
		{
			final SRP6aServer server = new SRP6aServer();
			server.setVerifier(verifier);

			final SRP6aClient client = new SRP6aClient();

			final BigInteger clientPublicKey = client.generatePublicValue();
			final BigInteger serverPublicKey = server.generatePublicValue();

			client.setServerCredentials(salt, serverPublicKey);
			server.setClientPublicKey(clientPublicKey);

			final BigInteger clientSessionKey = client.computeSessionKey(identity,
				password.clone());
			final BigInteger serverSessionKey = server.computeSessionKey();

			assertEquals(clientSessionKey, serverSessionKey,
				"Round " + i + ": Session keys should match");

			final BigInteger clientProof = client.computeProof(clientSessionKey);
			assertTrue(server.verifyClientProof(clientProof, serverSessionKey),
				"Round " + i + ": Client proof should be valid");

			final BigInteger serverProof = server.computeServerProof(clientProof, serverSessionKey);
			assertTrue(client.verifyServerProof(serverProof, clientSessionKey),
				"Round " + i + ": Server proof should be valid");
		}
	}

}
