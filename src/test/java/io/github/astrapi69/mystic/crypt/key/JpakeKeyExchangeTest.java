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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;

import javax.crypto.SecretKey;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.agreement.jpake.JPAKEParticipant;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound1Payload;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound2Payload;
import org.bouncycastle.crypto.agreement.jpake.JPAKERound3Payload;
import org.junit.jupiter.api.Test;

/**
 * The unit test class for the class {@link JpakeKeyExchange}
 */
public class JpakeKeyExchangeTest
{

	/**
	 * Test method for {@link JpakeKeyExchange#newParticipant(String, char[])} and
	 * {@link JpakeKeyExchange#deriveSharedSecret(BigInteger, int)}: two parties with the same
	 * password derive the same shared secret, and round 3 key confirmation succeeds.
	 */
	@Test
	public void testSamePasswordDerivesSameSecret() throws Exception
	{
		final JPAKEParticipant alice = JpakeKeyExchange.newParticipant("alice",
			"correct horse battery staple".toCharArray());
		final JPAKEParticipant bob = JpakeKeyExchange.newParticipant("bob",
			"correct horse battery staple".toCharArray());

		final JPAKERound1Payload aliceR1 = alice.createRound1PayloadToSend();
		final JPAKERound1Payload bobR1 = bob.createRound1PayloadToSend();
		alice.validateRound1PayloadReceived(bobR1);
		bob.validateRound1PayloadReceived(aliceR1);

		final JPAKERound2Payload aliceR2 = alice.createRound2PayloadToSend();
		final JPAKERound2Payload bobR2 = bob.createRound2PayloadToSend();
		alice.validateRound2PayloadReceived(bobR2);
		bob.validateRound2PayloadReceived(aliceR2);

		final BigInteger aliceKeyingMaterial = alice.calculateKeyingMaterial();
		final BigInteger bobKeyingMaterial = bob.calculateKeyingMaterial();

		// round 3: explicit key confirmation must succeed for matching passwords
		final JPAKERound3Payload aliceR3 = alice.createRound3PayloadToSend(aliceKeyingMaterial);
		final JPAKERound3Payload bobR3 = bob.createRound3PayloadToSend(bobKeyingMaterial);
		alice.validateRound3PayloadReceived(bobR3, aliceKeyingMaterial);
		bob.validateRound3PayloadReceived(aliceR3, bobKeyingMaterial);

		final SecretKey aliceSecret = JpakeKeyExchange.deriveSharedSecret(aliceKeyingMaterial, 32);
		final SecretKey bobSecret = JpakeKeyExchange.deriveSharedSecret(bobKeyingMaterial, 32);

		assertArrayEquals(aliceSecret.getEncoded(), bobSecret.getEncoded());
	}

	/**
	 * Test method proving round 3 key confirmation fails for two parties with different passwords.
	 */
	@Test
	public void testDifferentPasswordFailsRound3Confirmation() throws Exception
	{
		final JPAKEParticipant alice = JpakeKeyExchange.newParticipant("alice",
			"passwordA".toCharArray());
		final JPAKEParticipant bob = JpakeKeyExchange.newParticipant("bob",
			"passwordB".toCharArray());

		final JPAKERound1Payload aliceR1 = alice.createRound1PayloadToSend();
		final JPAKERound1Payload bobR1 = bob.createRound1PayloadToSend();
		alice.validateRound1PayloadReceived(bobR1);
		bob.validateRound1PayloadReceived(aliceR1);

		final JPAKERound2Payload aliceR2 = alice.createRound2PayloadToSend();
		final JPAKERound2Payload bobR2 = bob.createRound2PayloadToSend();
		alice.validateRound2PayloadReceived(bobR2);
		bob.validateRound2PayloadReceived(aliceR2);

		final BigInteger aliceKeyingMaterial = alice.calculateKeyingMaterial();
		final BigInteger bobKeyingMaterial = bob.calculateKeyingMaterial();
		assertFalse(aliceKeyingMaterial.equals(bobKeyingMaterial));

		final JPAKERound3Payload aliceR3 = alice.createRound3PayloadToSend(aliceKeyingMaterial);
		assertThrows(CryptoException.class,
			() -> bob.validateRound3PayloadReceived(aliceR3, bobKeyingMaterial));
	}

}
