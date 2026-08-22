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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;

import org.junit.jupiter.api.Test;

/**
 * Mutation-focused tests for {@link SRP6aClient} and {@link SRP6aVerifierGenerator}: the
 * secure-wipe of the caller supplied password array and the exact boolean result of
 * {@link SRP6aClient#verifyServerProof(BigInteger, BigInteger)}.
 */
class SrpWipeAndProofTest
{

	private static boolean allZero(char[] array)
	{
		for (char c : array)
		{
			if (c != '\0')
			{
				return false;
			}
		}
		return true;
	}

	@Test
	void generateVerifierWipesTheCallersPassword()
	{
		// kills the removed Arrays.fill(password, '\0') call in generateVerifier
		final SRP6aVerifierGenerator generator = new SRP6aVerifierGenerator();
		final byte[] salt = generator.generateSalt();
		final char[] password = "testPassword123".toCharArray();
		generator.generateVerifier("testuser", password, salt);
		assertTrue(allZero(password), "password array must be wiped after generateVerifier");
	}

	@Test
	void computeSessionKeyWipesTheCallersPassword()
	{
		// kills the removed Arrays.fill(password, '\0') call in computeSessionKey
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

		final char[] toWipe = password.clone();
		client.computeSessionKey(identity, toWipe);
		assertTrue(allZero(toWipe), "password array must be wiped after computeSessionKey");
	}

	@Test
	void verifyServerProofReturnsFalseForAnIncorrectProof()
	{
		// kills the "replaced boolean return with true" mutant of verifyServerProof: with a valid
		// session key but a bogus server proof the method must return false via the equals() check,
		// not the null-guard path
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
		final BigInteger clientProof = client.computeProof(clientSessionKey);
		final BigInteger genuineServerProof = server.computeServerProof(clientProof,
			serverSessionKey);

		// a tampered / wrong proof must be rejected ...
		assertFalse(
			client.verifyServerProof(genuineServerProof.add(BigInteger.ONE), clientSessionKey));
		// ... while the genuine one is accepted (guards against a trivially-false mutant too)
		assertTrue(client.verifyServerProof(genuineServerProof, clientSessionKey));
	}
}
