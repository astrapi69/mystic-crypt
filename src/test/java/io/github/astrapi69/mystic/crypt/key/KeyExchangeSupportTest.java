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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Unit tests for the input handling of {@link KeyExchangeSupport}: the paths a person reaches by
 * handing in the wrong file, which are exactly the ones that have to say what is wrong.
 */
class KeyExchangeSupportTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	@Test
	void everyOfferedAlgorithmCanSetUpAPartyAndBeReadBackFromItsStoredForm() throws Exception
	{
		for (String algorithm : KeyExchangeSupport.algorithms())
		{
			KeyExchangeSupport.Party party = KeyExchangeSupport.newParty(algorithm);

			KeyExchangeSupport.Party restored = KeyExchangeSupport
				.partyFrom(KeyExchangeSupport.privateKeyOf(party));

			assertEquals(algorithm, restored.algorithm());
			assertArrayEquals(party.first().getPublic().getEncoded(),
				restored.first().getPublic().getEncoded(),
				"the restored party must hold the same key as the stored one, for " + algorithm);
			assertEquals(algorithm,
				KeyExchangeSupport.algorithmOf(KeyExchangeSupport.publicKeyOf(party)));
		}
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "not from here", "MCKX1", "NOPE$PRV$X25519$AAAA$BBBB" })
	void aStoredKeyThatIsNotOneIsNamedAsSuch(String text)
	{
		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> KeyExchangeSupport.partyFrom(text));

		assertEquals("this is not a stored key of this tool", rejected.getMessage());
	}

	@Test
	void aStoredPrivateKeyMissingItsHalvesIsCalledIncomplete()
	{
		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> KeyExchangeSupport.partyFrom("MCKX1$PRV$X25519$AAAA"));

		assertEquals("this stored key is incomplete", rejected.getMessage());
	}

	@Test
	void aStoredHybridKeyWithOnlyOneHalfSaysWhichHalfIsMissing()
	{
		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> KeyExchangeSupport
				.partyFrom("MCKX1$PRV$" + KeyExchangeSupport.HYBRID + "$AAAA$BBBB$CCCC"));

		assertEquals("a stored hybrid key carries two halves and this one carries one",
			rejected.getMessage());
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "nope", "MCKX1$PUB", "NOPE$PUB$X25519" })
	void anEnvelopeWhoseAlgorithmCannotBeReadIsNamedAsNotFromThisTool(String envelope)
	{
		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> KeyExchangeSupport.algorithmOf(envelope));

		assertTrue(rejected.getMessage().contains("is not from this tool"),
			"the message was: '" + rejected.getMessage() + "'");
	}

	@ParameterizedTest
	@NullAndEmptySource
	@ValueSource(strings = { "   " })
	void nothingToReadIsSaidPlainly(String envelope)
	{
		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> KeyExchangeSupport.encapsulate(envelope));

		assertEquals("there is nothing to read", rejected.getMessage());
	}

	@ParameterizedTest
	@ValueSource(strings = { "MCKX1$PUB$X25519", "NOPE$PUB$X25519$AAAA" })
	void anEnvelopeTooShortOrWithAForeignPrefixIsNamedAsNotFromThisTool(String envelope)
	{
		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> KeyExchangeSupport.encapsulate(envelope));

		assertTrue(rejected.getMessage().contains("is not from this tool"),
			"the message was: '" + rejected.getMessage() + "'");
	}

	@Test
	void aHandshakeWhereAPublicKeyBelongsIsNamedAsAHandshake()
	{
		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> KeyExchangeSupport.encapsulate("MCKX1$HS$X25519$AAAA"));

		assertEquals("this is a handshake, and a public key was expected", rejected.getMessage());
	}

	@Test
	void aPublicKeyWhereAHandshakeBelongsIsNamedAsAPublicKey() throws Exception
	{
		KeyExchangeSupport.Party party = KeyExchangeSupport.newParty(KeyExchangeSupport.X25519);

		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> KeyExchangeSupport.decapsulate(party, "MCKX1$PUB$X25519$AAAA"));

		assertEquals("this is a public key, and a handshake was expected", rejected.getMessage());
	}

	@Test
	void aHybridEnvelopeCarryingOnlyOneHalfIsNamedByItsKind()
	{
		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> KeyExchangeSupport
				.encapsulate("MCKX1$PUB$" + KeyExchangeSupport.HYBRID + "$AAAA"));

		assertEquals("a hybrid pub carries two halves and this one carries one",
			rejected.getMessage());
	}

	@Test
	void anUnknownAlgorithmListsTheOnesThatExist()
	{
		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> KeyExchangeSupport.newParty("ML-KEM-2048"));

		assertTrue(
			rejected.getMessage().contains("is not one of")
				&& rejected.getMessage().contains(KeyExchangeSupport.ML_KEM_768),
			"the message must list the algorithms, but was: '" + rejected.getMessage() + "'");
	}

	/**
	 * The length checks sit exactly one part away from a usable envelope, so both sides of each
	 * boundary are pinned: three parts is enough to read an algorithm, two is not; five parts is a
	 * complete stored key, four is not.
	 */
	@Test
	void theShortestUsableEnvelopeIsAcceptedAndOnePartLessIsNot()
	{
		assertEquals("X25519", KeyExchangeSupport.algorithmOf("MCKX1$PUB$X25519"),
			"three parts carry an algorithm");
		assertThrows(IllegalArgumentException.class,
			() -> KeyExchangeSupport.algorithmOf("MCKX1$PUB"));
	}

	@Test
	void theShortestCompleteStoredKeyIsAcceptedAndOnePartLessIsCalledIncomplete() throws Exception
	{
		KeyExchangeSupport.Party party = KeyExchangeSupport.newParty(KeyExchangeSupport.X25519);
		String stored = KeyExchangeSupport.privateKeyOf(party);
		assertEquals(5, stored.split("\\$").length, "an X25519 stored key has five parts");

		assertEquals(KeyExchangeSupport.X25519, KeyExchangeSupport.partyFrom(stored).algorithm());

		String oneShort = stored.substring(0, stored.lastIndexOf('$'));
		IllegalArgumentException rejected = assertThrows(IllegalArgumentException.class,
			() -> KeyExchangeSupport.partyFrom(oneShort));
		assertEquals("this stored key is incomplete", rejected.getMessage());
	}

	@Test
	void aMessageEncryptedWithTheSharedSecretComesBackThroughIt() throws Exception
	{
		KeyExchangeSupport.Party party = KeyExchangeSupport.newParty(KeyExchangeSupport.ML_KEM_768);
		KeyExchangeSupport.Handshake handshake = KeyExchangeSupport
			.encapsulate(KeyExchangeSupport.publicKeyOf(party));
		byte[] message = "over the wire".getBytes(StandardCharsets.UTF_8);

		String encrypted = KeyExchangeSupport.encryptMessage(handshake.sharedSecret(), message);

		assertArrayEquals(message,
			KeyExchangeSupport.decryptMessage(handshake.sharedSecret(), encrypted));
		assertEquals(8, KeyExchangeSupport.fingerprintOf(handshake.sharedSecret()).length());
	}
}
