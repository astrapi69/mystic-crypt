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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

import javax.crypto.SecretKey;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.mystic.crypt.aead.KeyCommittingAeadEncryptor;

/**
 * A key exchange between two people who each hold only their own half, in three steps that can run
 * in three separate invocations:
 * <ul>
 * <li>the recipient generates a key pair and hands out the public half</li>
 * <li>the sender takes that public half, encapsulates against it, and gets a secret plus a
 * handshake to send back</li>
 * <li>the recipient feeds the handshake to its private half and arrives at the same secret</li>
 * </ul>
 * <p>
 * The three families differ in what actually travels, and this is what hides the difference. ML-KEM
 * produces a ciphertext. X25519 has no ciphertext at all: the sender makes an ephemeral key pair
 * and its public half is what travels. The hybrid does both and mixes the results. Every piece of
 * text carries the algorithm it belongs to, so nobody has to know which of the three they are
 * holding.
 * <p>
 * Nothing here is a secret in transit: what travels is a public key and a handshake, and someone
 * who reads both still cannot derive the shared secret.
 */
public final class KeyExchangeSupport
{

	/** What every stored key and every handshake of this tool starts with. */
	public static final String PREFIX = "MCKX1";

	/** The elliptic-curve algorithm, which has no ciphertext. */
	public static final String X25519 = "X25519";

	/** The ML-KEM parameter sets. */
	public static final String ML_KEM_512 = "ML-KEM-512";

	/** The ML-KEM parameter set of medium strength, and the one the hybrid uses. */
	public static final String ML_KEM_768 = "ML-KEM-768";

	/** The strongest ML-KEM parameter set. */
	public static final String ML_KEM_1024 = "ML-KEM-1024";

	/** The hybrid of the classical and the post-quantum exchange. */
	public static final String HYBRID = "Hybrid X25519 + ML-KEM-768";

	/** Length in bytes of the derived shared secret, an AES-256 key. */
	public static final int SECRET_LENGTH = 32;

	/** The envelope kind of a public key. */
	private static final String PUBLIC_KIND = "PUB";

	/** The envelope kind of a stored private key. */
	private static final String PRIVATE_KIND = "PRV";

	/** The envelope kind of a handshake. */
	private static final String HANDSHAKE_KIND = "HS";

	/** The field separator inside an envelope. */
	private static final String SEPARATOR = "$";

	private KeyExchangeSupport()
	{
	}

	/**
	 * What one side keeps to itself. The public half is handed out with
	 * {@link #publicKeyOf(Party)}.
	 *
	 * @param algorithm
	 *            one of {@link #algorithms()}
	 * @param first
	 *            the key pair, or the X25519 half of a hybrid one
	 * @param second
	 *            the ML-KEM half of a hybrid key pair, null for the other algorithms
	 */
	public record Party(String algorithm, KeyPair first, KeyPair second) {
	}

	/**
	 * What the sender ends up with: a secret to use, and a handshake for the other side.
	 *
	 * @param sharedSecret
	 *            the secret both sides will hold
	 * @param handshake
	 *            the text to send back to the recipient
	 */
	public record Handshake(SecretKey sharedSecret, String handshake) {
	}

	/**
	 * The algorithms this exchange offers, in the order they are shown.
	 *
	 * @return the algorithm names
	 */
	public static List<String> algorithms()
	{
		return List.of(ML_KEM_768, ML_KEM_512, ML_KEM_1024, X25519, HYBRID);
	}

	/**
	 * Sets up one side of an exchange.
	 *
	 * @param algorithm
	 *            one of {@link #algorithms()}
	 * @return the party, whose public half is handed to the other side
	 * @throws Exception
	 *             if this machine cannot produce such a key pair
	 */
	public static Party newParty(final String algorithm) throws Exception
	{
		if (X25519.equals(algorithm))
		{
			return new Party(algorithm, X25519KeyExchange.newKeyPair(), null);
		}
		if (HYBRID.equals(algorithm))
		{
			final HybridKemKeyExchange.HybridKeyPair hybrid = HybridKemKeyExchange
				.newHybridKeyPair(KeyPairGeneratorAlgorithm.ML_KEM_768);
			return new Party(algorithm, hybrid.getX25519KeyPair(), hybrid.getMlKemKeyPair());
		}
		return new Party(algorithm, MlKemKeyExchange.newKeyPair(mlKemAlgorithm(algorithm)), null);
	}

	/**
	 * The public half of a party, as one line of text to hand to the other side.
	 *
	 * @param party
	 *            the party
	 * @return the public key as text
	 */
	public static String publicKeyOf(final Party party)
	{
		if (party.second() != null)
		{
			return envelope(PUBLIC_KIND, party.algorithm(), party.first().getPublic().getEncoded(),
				party.second().getPublic().getEncoded());
		}
		return envelope(PUBLIC_KIND, party.algorithm(), party.first().getPublic().getEncoded(),
			null);
	}

	/**
	 * The whole of one side, private halves included, as one line of text, so a party can be put
	 * away and taken up again in another run of the command line.
	 * <p>
	 * This text is the private key. Whoever holds it can read everything that was ever sent to this
	 * party, so it belongs where a private key belongs and not next to the public one.
	 *
	 * @param party
	 *            the party
	 * @return the party as text
	 */
	public static String privateKeyOf(final Party party)
	{
		final StringBuilder text = new StringBuilder(PREFIX).append(SEPARATOR).append(PRIVATE_KIND)
			.append(SEPARATOR).append(party.algorithm()).append(SEPARATOR)
			.append(encode(party.first().getPrivate().getEncoded())).append(SEPARATOR)
			.append(encode(party.first().getPublic().getEncoded()));
		if (party.second() != null)
		{
			text.append(SEPARATOR).append(encode(party.second().getPrivate().getEncoded()))
				.append(SEPARATOR).append(encode(party.second().getPublic().getEncoded()));
		}
		return text.toString();
	}

	/**
	 * Takes up a party that {@link #privateKeyOf(Party)} put away.
	 *
	 * @param text
	 *            what {@link #privateKeyOf(Party)} produced
	 * @return the party, ready to decapsulate again
	 * @throws Exception
	 *             if the text is not a stored party or its keys cannot be read
	 */
	public static Party partyFrom(final String text) throws Exception
	{
		final String[] parts = text == null ? new String[0] : text.trim().split("\\$");
		// The kind is read before the length, and that order is the whole point: a public key has
		// fewer parts than a private one, so a length check first would call a perfectly good
		// public key "not a key of this tool" and send the reader looking in the wrong place.
		if (parts.length < 2 || !PREFIX.equals(parts[0]))
		{
			throw new IllegalArgumentException("this is not a stored key of this tool");
		}
		if (!PRIVATE_KIND.equals(parts[1]))
		{
			throw new IllegalArgumentException(
				"this is the public half; the private key of this side is needed here");
		}
		if (parts.length < 5)
		{
			throw new IllegalArgumentException("this stored key is incomplete");
		}
		final String algorithm = parts[2];
		final boolean hybrid = HYBRID.equals(algorithm);
		if (hybrid && parts.length < 7)
		{
			throw new IllegalArgumentException(
				"a stored hybrid key carries two halves and this one carries one");
		}
		final String first = hybrid ? X25519 : algorithm;
		final KeyPair firstPair = new KeyPair(toPublicKey(decode(parts[4]), first),
			toPrivateKey(decode(parts[3]), first));
		if (!hybrid)
		{
			return new Party(algorithm, firstPair, null);
		}
		final KeyPair secondPair = new KeyPair(toPublicKey(decode(parts[6]), ML_KEM_768),
			toPrivateKey(decode(parts[5]), ML_KEM_768));
		return new Party(algorithm, firstPair, secondPair);
	}

	/**
	 * The sender's side: takes the recipient's public half and produces a secret and a handshake.
	 *
	 * @param recipientPublicKey
	 *            what the recipient handed out
	 * @return the shared secret and the handshake to send back
	 * @throws Exception
	 *             if the public key cannot be read or the exchange fails
	 */
	public static Handshake encapsulate(final String recipientPublicKey) throws Exception
	{
		final String[] parts = read(PUBLIC_KIND, recipientPublicKey);
		final String algorithm = parts[2];
		final byte[] firstKey = decode(parts[3]);
		if (X25519.equals(algorithm))
		{
			// there is no ciphertext in an elliptic curve exchange: the sender makes an ephemeral
			// key pair, and its public half is what travels
			final KeyPair ephemeral = X25519KeyExchange.newKeyPair();
			final SecretKey secret = X25519KeyExchange.deriveSharedSecret(ephemeral.getPrivate(),
				toPublicKey(firstKey, X25519), SECRET_LENGTH);
			return new Handshake(secret,
				envelope(HANDSHAKE_KIND, algorithm, ephemeral.getPublic().getEncoded(), null));
		}
		if (HYBRID.equals(algorithm))
		{
			final byte[] secondKey = decode(parts[4]);
			final HybridKemKeyExchange.HybridEncapsulation encapsulation = HybridKemKeyExchange
				.hybridEncapsulate(toPublicKey(firstKey, X25519),
					toPublicKey(secondKey, ML_KEM_768), KeyPairGeneratorAlgorithm.ML_KEM_768,
					SECRET_LENGTH);
			return new Handshake(encapsulation.getSharedSecret(),
				envelope(HANDSHAKE_KIND, algorithm, encapsulation.getMlKemCiphertext(),
					encapsulation.getSenderX25519PublicKey().getEncoded()));
		}
		final MlKemKeyExchange.Encapsulation encapsulation = MlKemKeyExchange
			.encapsulate(toPublicKey(firstKey, algorithm), mlKemAlgorithm(algorithm));
		return new Handshake(encapsulation.getSharedSecret(),
			envelope(HANDSHAKE_KIND, algorithm, encapsulation.getCiphertext(), null));
	}

	/**
	 * The recipient's side: takes the handshake and arrives at the same secret.
	 *
	 * @param party
	 *            the recipient, holding the private half
	 * @param handshake
	 *            what came back from the sender
	 * @return the shared secret, the same one the sender holds
	 * @throws Exception
	 *             if the handshake does not belong to this party or cannot be read
	 */
	public static SecretKey decapsulate(final Party party, final String handshake) throws Exception
	{
		final String[] parts = read(HANDSHAKE_KIND, handshake);
		final String algorithm = parts[2];
		if (!party.algorithm().equals(algorithm))
		{
			throw new IllegalArgumentException("this handshake is for " + algorithm
				+ " and these keys are for " + party.algorithm());
		}
		final byte[] first = decode(parts[3]);
		if (X25519.equals(algorithm))
		{
			return X25519KeyExchange.deriveSharedSecret(party.first().getPrivate(),
				toPublicKey(first, X25519), SECRET_LENGTH);
		}
		if (HYBRID.equals(algorithm))
		{
			final byte[] senderPublicKey = decode(parts[4]);
			return HybridKemKeyExchange.hybridDecapsulate(party.first().getPrivate(),
				party.second().getPrivate(), toPublicKey(senderPublicKey, X25519), first,
				KeyPairGeneratorAlgorithm.ML_KEM_768, SECRET_LENGTH);
		}
		return MlKemKeyExchange.decapsulate(party.first().getPrivate(), first,
			mlKemAlgorithm(algorithm));
	}

	/**
	 * Encrypts a message with a shared secret, so the secret is used for something rather than only
	 * looked at.
	 *
	 * @param sharedSecret
	 *            the secret both sides hold
	 * @param message
	 *            what to encrypt
	 * @return the encrypted message as base64
	 * @throws Exception
	 *             if encrypting fails
	 */
	public static String encryptMessage(final SecretKey sharedSecret, final byte[] message)
		throws Exception
	{
		return encode(new KeyCommittingAeadEncryptor(sharedSecret).encrypt(message));
	}

	/**
	 * Decrypts what {@link #encryptMessage(SecretKey, byte[])} produced. A secret that is not the
	 * same one fails here rather than producing rubbish.
	 *
	 * @param sharedSecret
	 *            the secret
	 * @param encrypted
	 *            the encrypted message as base64
	 * @return the message
	 * @throws Exception
	 *             if the secret is wrong or the message was changed
	 */
	public static byte[] decryptMessage(final SecretKey sharedSecret, final String encrypted)
		throws Exception
	{
		return new KeyCommittingAeadEncryptor(sharedSecret).decrypt(decode(encrypted.trim()));
	}

	/**
	 * A short value over a secret, so two sides can compare that they arrived at the same one by
	 * reading it out, without either of them showing the secret itself.
	 *
	 * @param sharedSecret
	 *            the secret
	 * @return eight hex characters
	 * @throws Exception
	 *             if the digest is unavailable
	 */
	public static String fingerprintOf(final SecretKey sharedSecret) throws Exception
	{
		final byte[] digest = MessageDigest.getInstance("SHA-256")
			.digest(sharedSecret.getEncoded());
		return HexFormat.of().formatHex(digest).substring(0, 8);
	}

	/**
	 * Which algorithm a public key or a handshake belongs to.
	 *
	 * @param envelope
	 *            the text
	 * @return the algorithm name
	 */
	public static String algorithmOf(final String envelope)
	{
		final String[] parts = envelope == null ? new String[0] : envelope.trim().split("\\$");
		if (parts.length < 3 || !PREFIX.equals(parts[0]))
		{
			throw new IllegalArgumentException("'" + envelope + "' is not from this tool");
		}
		return parts[2];
	}

	private static String encode(final byte[] bytes)
	{
		return Base64.getEncoder().encodeToString(bytes);
	}

	private static byte[] decode(final String text)
	{
		return Base64.getDecoder().decode(text);
	}

	private static String envelope(final String kind, final String algorithm, final byte[] first,
		final byte[] second)
	{
		final StringBuilder text = new StringBuilder(PREFIX).append(SEPARATOR).append(kind)
			.append(SEPARATOR).append(algorithm).append(SEPARATOR).append(encode(first));
		if (second != null)
		{
			text.append(SEPARATOR).append(encode(second));
		}
		return text.toString();
	}

	private static String[] read(final String expectedKind, final String envelope)
	{
		if (envelope == null || envelope.isBlank())
		{
			throw new IllegalArgumentException("there is nothing to read");
		}
		final String[] parts = envelope.trim().split("\\$");
		if (parts.length < 4 || !PREFIX.equals(parts[0]))
		{
			throw new IllegalArgumentException("'" + envelope + "' is not from this tool");
		}
		if (!expectedKind.equals(parts[1]))
		{
			throw new IllegalArgumentException("this is " + (PUBLIC_KIND.equals(parts[1])
				? "a public key, and a handshake was " + "expected"
				: "a handshake, and a public key was expected"));
		}
		if (HYBRID.equals(parts[2]) && parts.length < 5)
		{
			throw new IllegalArgumentException("a hybrid " + expectedKind.toLowerCase(Locale.ROOT)
				+ " carries two halves and this one carries one");
		}
		return parts;
	}

	private static PublicKey toPublicKey(final byte[] encoded, final String algorithm)
		throws Exception
	{
		return keyFactory(algorithm).generatePublic(new X509EncodedKeySpec(encoded));
	}

	private static PrivateKey toPrivateKey(final byte[] encoded, final String algorithm)
		throws Exception
	{
		return keyFactory(algorithm).generatePrivate(new PKCS8EncodedKeySpec(encoded));
	}

	private static KeyFactory keyFactory(final String algorithm) throws Exception
	{
		return KeyFactory.getInstance(algorithm.startsWith("ML-KEM") ? "ML-KEM" : algorithm);
	}

	private static KeyPairGeneratorAlgorithm mlKemAlgorithm(final String algorithm)
	{
		return switch (algorithm)
		{
			case ML_KEM_512 -> KeyPairGeneratorAlgorithm.ML_KEM_512;
			case ML_KEM_768 -> KeyPairGeneratorAlgorithm.ML_KEM_768;
			case ML_KEM_1024 -> KeyPairGeneratorAlgorithm.ML_KEM_1024;
			default -> throw new IllegalArgumentException(
				"'" + algorithm + "' is not one of " + String.join(", ", algorithms()));
		};
	}
}
