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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The unit test class for the argument validation of the classes {@link SRP6aClient} and
 * {@link SRP6aServer}
 */
class SrpParameterValidationTest
{

	private static final String IDENTITY = "alice";

	private static final char[] PASSWORD = "password123".toCharArray();

	/**
	 * A scenario with a call that has to be rejected
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param executable
	 *            the call that has to be rejected
	 * @param expectedMessage
	 *            the expected message of the thrown exception
	 */
	record RejectedCallCase(String description, Executable executable, String expectedMessage) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static Stream<RejectedCallCase> rejectedClientCalls()
	{
		return Stream.of(
			new RejectedCallCase("client without the group modulus",
				() -> new SRP6aClient(null, SRP6aVerifierGenerator.DEFAULT_G,
					SRP6aVerifierGenerator.DEFAULT_HASH_ALGORITHM),
				"Parameters cannot be null"),
			new RejectedCallCase("client without the generator",
				() -> new SRP6aClient(SRP6aVerifierGenerator.DEFAULT_N, null,
					SRP6aVerifierGenerator.DEFAULT_HASH_ALGORITHM),
				"Parameters cannot be null"),
			new RejectedCallCase("client without the hash algorithm",
				() -> new SRP6aClient(SRP6aVerifierGenerator.DEFAULT_N,
					SRP6aVerifierGenerator.DEFAULT_G, null),
				"Parameters cannot be null"),
			new RejectedCallCase("session key without an identity",
				() -> newClientWithServerCredentials().computeSessionKey(null, PASSWORD.clone()),
				"Identity cannot be null"),
			new RejectedCallCase("session key without a password",
				() -> newClientWithServerCredentials().computeSessionKey(IDENTITY, null),
				"Password cannot be null"),
			new RejectedCallCase("session key without server credentials", () -> {
				SRP6aClient client = new SRP6aClient();
				client.generatePublicValue();
				client.computeSessionKey(IDENTITY, PASSWORD.clone());
			}, "Server credentials not set"),
			new RejectedCallCase("proof without a session key",
				() -> new SRP6aClient().computeProof(null), "Session key cannot be null"),
			new RejectedCallCase("proof without an established session",
				() -> new SRP6aClient().computeProof(BigInteger.ONE), "Credentials not set"),
			new RejectedCallCase("proof with a public value but without server credentials", () -> {
				SRP6aClient client = new SRP6aClient();
				client.generatePublicValue();
				client.computeProof(BigInteger.ONE);
			}, "Credentials not set"),
			new RejectedCallCase("proof with server credentials but without a session key",
				() -> newClientWithServerCredentials().computeProof(BigInteger.ONE),
				"Credentials not set"),
			new RejectedCallCase("session key with server credentials set before the public value",
				() -> {
					SRP6aClient client = new SRP6aClient();
					client.computeProof(BigInteger.ONE);
				}, "Credentials not set"),
			new RejectedCallCase("session key after a rejected server public value", () -> {
				SRP6aClient client = new SRP6aClient();
				client.generatePublicValue();
				// B = N is congruent to zero and therefore an invalid server public value
				try
				{
					client.setServerCredentials(new byte[16], SRP6aVerifierGenerator.DEFAULT_N);
				}
				catch (SecurityException expected)
				{
					// the salt is kept but the server public value stays unset
				}
				client.computeSessionKey(IDENTITY, PASSWORD.clone());
			}, "Server credentials not set"));
	}

	static Stream<RejectedCallCase> rejectedServerCalls()
	{
		return Stream.of(
			new RejectedCallCase("server without the group modulus",
				() -> new SRP6aServer(null, SRP6aVerifierGenerator.DEFAULT_G,
					SRP6aVerifierGenerator.DEFAULT_HASH_ALGORITHM),
				"Parameters cannot be null"),
			new RejectedCallCase("server without the generator",
				() -> new SRP6aServer(SRP6aVerifierGenerator.DEFAULT_N, null,
					SRP6aVerifierGenerator.DEFAULT_HASH_ALGORITHM),
				"Parameters cannot be null"),
			new RejectedCallCase("server without the hash algorithm",
				() -> new SRP6aServer(SRP6aVerifierGenerator.DEFAULT_N,
					SRP6aVerifierGenerator.DEFAULT_G, null),
				"Parameters cannot be null"),
			new RejectedCallCase("verifier is null", () -> new SRP6aServer().setVerifier(null),
				"Verifier cannot be null"),
			new RejectedCallCase("server proof without a client proof",
				() -> new SRP6aServer().computeServerProof(null, BigInteger.ONE),
				"Client proof cannot be null"),
			new RejectedCallCase("server proof without a session key",
				() -> new SRP6aServer().computeServerProof(BigInteger.ONE, null),
				"Session key cannot be null"),
			new RejectedCallCase("server proof without a client public key",
				() -> new SRP6aServer().computeServerProof(BigInteger.ONE, BigInteger.ONE),
				"Client public key not set"),
			new RejectedCallCase("server proof without an established session", () -> {
				SRP6aServer server = newServerWithVerifier();
				server.generatePublicValue();
				server.setClientPublicKey(newClientPublicValue());
				server.computeServerProof(BigInteger.ONE, BigInteger.ONE);
			}, "Session not established"));
	}

	private static BigInteger newClientPublicValue()
	{
		SRP6aClient client = new SRP6aClient();
		return client.generatePublicValue();
	}

	private static SRP6aServer newServerWithVerifier()
	{
		SRP6aVerifierGenerator verifierGenerator = new SRP6aVerifierGenerator();
		byte[] salt = verifierGenerator.generateSalt();
		SRP6aServer server = new SRP6aServer();
		server.setVerifier(verifierGenerator.generateVerifier(IDENTITY, PASSWORD.clone(), salt));
		return server;
	}

	private static SRP6aClient newClientWithServerCredentials()
	{
		SRP6aVerifierGenerator verifierGenerator = new SRP6aVerifierGenerator();
		byte[] salt = verifierGenerator.generateSalt();
		SRP6aServer server = new SRP6aServer();
		server.setVerifier(verifierGenerator.generateVerifier(IDENTITY, PASSWORD.clone(), salt));
		SRP6aClient client = new SRP6aClient();
		client.generatePublicValue();
		client.setServerCredentials(salt, server.generatePublicValue());
		return client;
	}

	/**
	 * Test method for the argument validation of {@link SRP6aClient}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("rejectedClientCalls")
	void everyInvalidClientCallIsRejected(final RejectedCallCase testCase)
	{
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
			testCase.executable());

		assertEquals(testCase.expectedMessage(), exception.getMessage());
	}

	/**
	 * Test method for the argument validation of {@link SRP6aServer}
	 *
	 * @param testCase
	 *            the test case
	 */
	@ParameterizedTest
	@MethodSource("rejectedServerCalls")
	void everyInvalidServerCallIsRejected(final RejectedCallCase testCase)
	{
		Exception exception = assertThrows(Exception.class, testCase.executable());

		assertEquals(testCase.expectedMessage(), exception.getMessage());
	}

	/**
	 * Test method for {@link SRP6aServer#computeSessionKey()}, without a verifier no session key
	 * can be computed
	 */
	@Test
	void serverComputeSessionKeyWithoutVerifierIsRejected()
	{
		IllegalStateException exception = assertThrows(IllegalStateException.class,
			() -> new SRP6aServer().computeSessionKey());

		assertEquals("Verifier not set", exception.getMessage());
	}

	/**
	 * Test method for {@link SRP6aClient#verifyServerProof(BigInteger, BigInteger)}, a proof can
	 * never be verified before the session is established
	 */
	@Test
	void clientVerifyServerProofAnswersFalseWithoutAnEstablishedSession()
	{
		SRP6aClient client = new SRP6aClient();

		assertFalse(client.verifyServerProof(BigInteger.ONE, null));
		assertFalse(client.verifyServerProof(null, BigInteger.ONE));
		// the internally thrown IllegalArgumentException of computeProof must not escape
		assertFalse(client.verifyServerProof(BigInteger.ONE, BigInteger.ONE));
	}

	/**
	 * Test method for {@link SRP6aServer#verifyClientProof(BigInteger, BigInteger)}, a proof can
	 * never be verified before the session is established
	 */
	@Test
	void serverVerifyClientProofAnswersFalseWithoutAnEstablishedSession()
	{
		SRP6aServer server = newServerWithVerifier();

		assertFalse(server.verifyClientProof(BigInteger.ONE, null));
		assertFalse(server.verifyClientProof(null, BigInteger.ONE));
		// the public value of the server is not generated yet
		assertFalse(server.verifyClientProof(BigInteger.ONE, BigInteger.ONE));

		server.generatePublicValue();
		// the session key is not computed yet
		assertFalse(server.verifyClientProof(BigInteger.ONE, BigInteger.ONE));
	}

	/**
	 * Test method for {@link SRP6aServer#getPublicValue()} and
	 * {@link SRP6aClient#getPublicValue()}, the public value is only available after it was
	 * generated
	 */
	@Test
	void getPublicValueAnswersNullUntilItIsGenerated()
	{
		SRP6aServer server = newServerWithVerifier();
		SRP6aClient client = new SRP6aClient();

		assertNull(server.getPublicValue());
		assertNull(client.getPublicValue());

		BigInteger serverPublicValue = server.generatePublicValue();
		BigInteger clientPublicValue = client.generatePublicValue();

		assertEquals(serverPublicValue, server.getPublicValue());
		assertEquals(clientPublicValue, client.getPublicValue());
		assertTrue(serverPublicValue.signum() > 0);
		assertTrue(clientPublicValue.signum() > 0);
	}
}
