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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Tests for issue #112: an EC key pair can encrypt and decrypt, not only sign.
 * <p>
 * RSA has a direct public key primitive - encrypt with the public key, decrypt with the private
 * one. An EC key has none. ECIES is the equivalent: a shared secret is derived by ECDH against an
 * ephemeral key pair and the message is encrypted under that secret, so every encryption carries a
 * fresh public value with it and no two are alike.
 */
class EcEncryptDecryptTest
{

	private static final String MESSAGE = "the message under test, with unicode: Ärger, 漢字";

	@BeforeAll
	static void setUp()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	private static KeyPair newKeyPair(final String curve) throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC",
			BouncyCastleProvider.PROVIDER_NAME);
		generator.initialize(new ECGenParameterSpec(curve));
		return generator.generateKeyPair();
	}

	/**
	 * The property the pair owes: what one encrypts, the other opens - on every curve, not only the
	 * one that happened to be tried.
	 *
	 * @param curve
	 *            the named curve to generate on
	 * @throws Exception
	 *             if key generation, encryption or decryption fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "secp256r1", "secp384r1", "secp521r1", "secp256k1", "prime239v1",
			"brainpoolP256r1" })
	void whatThePublicKeyEncryptsThePrivateKeyOpens(final String curve) throws Exception
	{
		KeyPair keyPair = newKeyPair(curve);
		byte[] plain = MESSAGE.getBytes(StandardCharsets.UTF_8);

		byte[] encrypted = new EcPublicKeyEncryptor(keyPair.getPublic()).encrypt(plain);
		byte[] decrypted = new EcPrivateKeyDecryptor(keyPair.getPrivate()).decrypt(encrypted);

		assertArrayEquals(plain, decrypted, curve + " must come back as what went in");
		assertFalse(Arrays.equals(plain, encrypted),
			curve + " must not leave the message in clear");
	}

	/**
	 * The hex pair is what the user interface drives, so it is asserted through the same property.
	 *
	 * @param curve
	 *            the named curve to generate on
	 * @throws Exception
	 *             if key generation, encryption or decryption fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "secp256r1", "secp384r1", "secp521r1", "secp256k1", "prime239v1",
			"brainpoolP256r1" })
	void theHexPairRoundTripsOnEveryCurve(final String curve) throws Exception
	{
		KeyPair keyPair = newKeyPair(curve);

		String encrypted = new EcPublicKeyHexEncryptor(keyPair.getPublic()).encrypt(MESSAGE);
		String decrypted = new EcPrivateKeyHexDecryptor(keyPair.getPrivate()).decrypt(encrypted);

		assertEquals(MESSAGE, decrypted, curve + " must come back as what went in");
		assertTrue(encrypted.matches("[0-9a-f]+"),
			curve + " must produce hex, but was: " + encrypted.substring(0, 24));
	}

	/**
	 * A fresh ephemeral key pair per encryption is what makes the scheme safe, and it is
	 * observable: the same message under the same public key must not produce the same bytes twice.
	 *
	 * @throws Exception
	 *             if key generation or encryption fails
	 */
	@Test
	void encryptingTheSameMessageTwiceGivesDifferentBytes() throws Exception
	{
		KeyPair keyPair = newKeyPair("secp256r1");
		EcPublicKeyHexEncryptor encryptor = new EcPublicKeyHexEncryptor(keyPair.getPublic());

		assertNotEquals(encryptor.encrypt(MESSAGE), encryptor.encrypt(MESSAGE),
			"a fresh ephemeral key per encryption must make two encryptions differ");
	}

	/**
	 * The other half of the promise: a key that was not meant to open this must not open it.
	 *
	 * @throws Exception
	 *             if key generation or encryption fails
	 */
	@Test
	void anotherKeyDoesNotOpenIt() throws Exception
	{
		KeyPair keyPair = newKeyPair("secp256r1");
		KeyPair foreign = newKeyPair("secp256r1");
		String encrypted = new EcPublicKeyHexEncryptor(keyPair.getPublic()).encrypt(MESSAGE);

		assertThrows(Exception.class,
			() -> new EcPrivateKeyHexDecryptor(foreign.getPrivate()).decrypt(encrypted));
	}

	/**
	 * The scheme carries a mac, so a changed byte is refused rather than decrypted into rubbish.
	 *
	 * @throws Exception
	 *             if key generation or encryption fails
	 */
	@Test
	void aTamperedCipherTextIsRefused() throws Exception
	{
		KeyPair keyPair = newKeyPair("secp256r1");
		byte[] encrypted = new EcPublicKeyEncryptor(keyPair.getPublic())
			.encrypt(MESSAGE.getBytes(StandardCharsets.UTF_8));
		byte[] tampered = encrypted.clone();
		tampered[tampered.length / 2] ^= 0x01;

		assertThrows(Exception.class,
			() -> new EcPrivateKeyDecryptor(keyPair.getPrivate()).decrypt(tampered));
	}

	/**
	 * A key of the wrong kind is named rather than failing somewhere further in. RSA has its own
	 * pair; the agreement curves and the post-quantum families have no encryption primitive at all.
	 *
	 * @param algorithm
	 *            the algorithm whose key is offered
	 * @throws Exception
	 *             if key generation fails
	 */
	@ParameterizedTest
	@ValueSource(strings = { "RSA", "Ed25519", "X25519", "ML-KEM-768", "ML-DSA-65" })
	void aKeyThatIsNotAnEcKeyIsRefusedByName(final String algorithm) throws Exception
	{
		KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm,
			BouncyCastleProvider.PROVIDER_NAME);
		if ("RSA".equals(algorithm))
		{
			generator.initialize(2048);
		}
		KeyPair keyPair = generator.generateKeyPair();

		IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
			() -> new EcPublicKeyEncryptor(keyPair.getPublic()));

		assertTrue(refused.getMessage().contains(keyPair.getPublic().getAlgorithm()),
			"the message must name the algorithm, but was: " + refused.getMessage());
	}

	/** Nothing is not a key. */
	@Test
	void aMissingKeyIsRefusedOutright()
	{
		assertThrows(NullPointerException.class, () -> new EcPublicKeyEncryptor(null));
		assertThrows(NullPointerException.class, () -> new EcPrivateKeyDecryptor(null));
		assertThrows(NullPointerException.class, () -> new EcPublicKeyHexEncryptor(null));
		assertThrows(NullPointerException.class, () -> new EcPrivateKeyHexDecryptor(null));
	}
}
