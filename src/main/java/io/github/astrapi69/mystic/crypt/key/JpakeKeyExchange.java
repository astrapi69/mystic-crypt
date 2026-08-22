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

import java.math.BigInteger;
import java.util.Objects;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.agreement.jpake.JPAKEParticipant;

import io.github.astrapi69.crypt.api.algorithm.AesAlgorithm;
import io.github.astrapi69.crypt.data.factory.HkdfExtensions;

/**
 * The class {@link JpakeKeyExchange} establishes a shared {@link SecretKey} between two parties
 * that both know the same password, using J-PAKE (Password-Authenticated Key Exchange by Juggling)
 * - unlike {@link X25519KeyExchange}, the resulting key is only usable if both parties supplied the
 * same password, and a passive eavesdropper who intercepts every message exchanged learns nothing
 * usable for an offline dictionary attack on the password.
 * <p>
 * Unlike the other key-exchange classes in this package, J-PAKE is a three-round interactive
 * protocol: both parties must exchange two (or three, for explicit key confirmation) payloads over
 * some transport this library does not provide - only the cryptographic math is handled here, via
 * Bouncy Castle's {@link JPAKEParticipant}. Typical usage:
 *
 * <pre>
 * {
 * 	&#64;code
 * 	// both parties, out of band, agree on the same password
 * 	JPAKEParticipant alice = JpakeKeyExchange.newParticipant("alice", password);
 * 	JPAKEParticipant bob = JpakeKeyExchange.newParticipant("bob", password);
 *
 * 	// round 1: exchange payloads, then validate the peer's
 * 	JPAKERound1Payload aliceR1 = alice.createRound1PayloadToSend();
 * 	JPAKERound1Payload bobR1 = bob.createRound1PayloadToSend();
 * 	alice.validateRound1PayloadReceived(bobR1);
 * 	bob.validateRound1PayloadReceived(aliceR1);
 *
 * 	// round 2: same pattern
 * 	JPAKERound2Payload aliceR2 = alice.createRound2PayloadToSend();
 * 	JPAKERound2Payload bobR2 = bob.createRound2PayloadToSend();
 * 	alice.validateRound2PayloadReceived(bobR2);
 * 	bob.validateRound2PayloadReceived(aliceR2);
 *
 * 	// both sides now have matching keying material IF (and only if) the passwords matched
 * 	BigInteger aliceKeyingMaterial = alice.calculateKeyingMaterial();
 * 	BigInteger bobKeyingMaterial = bob.calculateKeyingMaterial();
 *
 * 	// optional but recommended: round 3 explicitly confirms the passwords matched, rather than
 * 	// silently proceeding with two different, unusable keys - see JPAKEParticipant's
 * 	// createRound3PayloadToSend/validateRound3PayloadReceived
 *
 * 	SecretKey sharedKey = JpakeKeyExchange.deriveSharedSecret(aliceKeyingMaterial, 32);
 * }
 * </pre>
 */
public final class JpakeKeyExchange
{

	private JpakeKeyExchange()
	{
	}

	/**
	 * Creates a new {@link JPAKEParticipant} with sane defaults (NIST 3072-bit prime order group,
	 * SHA-256, a default {@link java.security.SecureRandom}).
	 *
	 * @param participantId
	 *            a unique identifier of this participant; the two participants in the exchange must
	 *            not share the same id
	 * @param password
	 *            the shared secret; a defensive copy is made by {@link JPAKEParticipant} and
	 *            cleared once {@code calculateKeyingMaterial()} is called on it, but the caller is
	 *            still responsible for clearing this array afterwards
	 * @return the new participant, ready to create its round 1 payload
	 */
	public static JPAKEParticipant newParticipant(final String participantId, final char[] password)
	{
		Objects.requireNonNull(participantId);
		Objects.requireNonNull(password);
		return new JPAKEParticipant(participantId, password);
	}

	/**
	 * Derives a shared AES {@link SecretKey} of the given length from the raw J-PAKE keying
	 * material via HKDF key derivation, the same pattern used by
	 * {@link X25519KeyExchange#deriveSharedSecret(java.security.PrivateKey, java.security.PublicKey, int)}
	 * for its raw ECDH secret.
	 *
	 * @param keyingMaterial
	 *            the value returned by {@link JPAKEParticipant#calculateKeyingMaterial()}
	 * @param keyLengthBytes
	 *            the desired length in bytes of the derived key (e.g. 32 for AES-256)
	 * @return the derived shared {@link SecretKey}
	 */
	public static SecretKey deriveSharedSecret(final BigInteger keyingMaterial,
		final int keyLengthBytes)
	{
		Objects.requireNonNull(keyingMaterial);
		final byte[] derivedKeyBytes = HkdfExtensions.deriveKey(keyingMaterial.toByteArray(), null,
			null, keyLengthBytes);
		return new SecretKeySpec(derivedKeyBytes, AesAlgorithm.AES.getAlgorithm());
	}

}
