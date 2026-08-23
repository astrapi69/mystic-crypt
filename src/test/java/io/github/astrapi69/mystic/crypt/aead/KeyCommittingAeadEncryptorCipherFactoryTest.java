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
package io.github.astrapi69.mystic.crypt.aead;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.mystic.crypt.algorithm.MysticSymmetricAlgorithm;
import io.github.astrapi69.mystic.crypt.core.AbstractCryptor;

/**
 * The unit test class for the construction-time cipher factory of
 * {@link KeyCommittingAeadEncryptor}.
 * <p>
 * {@link AbstractCryptor#onInitialize()} calls {@code newCipher(key)} and publishes the result on
 * the {@link CryptModel} ({@code model.setCipher(...)} / {@code model.setInitialized(true)}), so
 * the cipher that {@link KeyCommittingAeadEncryptor#newCipher(SecretKey, String, byte[], int, int)}
 * builds is part of the observable state of every encryptor instance. Before these tests existed
 * the whole factory chain was only exercised, never inspected: no test looked at
 * {@code getModel().getCipher()} at all, so an implementation that returned {@code null} from
 * {@code newCipher(...)}, or that built the {@link Cipher} but never called
 * {@link Cipher#init(int, java.security.Key, java.security.spec.AlgorithmParameterSpec)} on it,
 * would have passed the whole suite. These tests guard exactly that: the encryptor must hand out an
 * existing, AES/GCM, ENCRYPT_MODE-initialised cipher with a fresh 96-bit nonce.
 * </p>
 *
 * @author Asterios Raptis
 */
class KeyCommittingAeadEncryptorCipherFactoryTest
{

	/** Length of the GCM nonce in bytes that {@code KeyCommittingAeadEncryptor} uses. */
	private static final int NONCE_LENGTH = 12;

	/**
	 * Length of the GCM authentication tag in bits that {@code KeyCommittingAeadEncryptor} uses.
	 */
	private static final int GCM_TAG_LENGTH_BITS = 128;

	private SecretKey testKey;

	/**
	 * A construction scenario for a {@link KeyCommittingAeadEncryptor}: both public constructors
	 * end up in {@link AbstractCryptor#onInitialize()}, so both have to produce the same
	 * construction-time cipher
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param fromCryptModel
	 *            true if the encryptor is built from a {@link CryptModel}, false if it is built
	 *            from a bare {@link SecretKey}
	 */
	record ConstructionCase(String description, boolean fromCryptModel) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static Stream<ConstructionCase> constructionCases()
	{
		return Stream.of(new ConstructionCase("constructed from a bare SecretKey", false),
			new ConstructionCase("constructed from a CryptModel", true));
	}

	@BeforeEach
	void setUp() throws Exception
	{
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		testKey = keyGen.generateKey();
	}

	private KeyCommittingAeadEncryptor newEncryptor(final ConstructionCase testCase)
		throws Exception
	{
		if (testCase.fromCryptModel())
		{
			CryptModel<Cipher, SecretKey, String> model = CryptModel
				.<Cipher, SecretKey, String> builder().key(testKey).build();
			return new KeyCommittingAeadEncryptor(model);
		}
		return new KeyCommittingAeadEncryptor(testKey);
	}

	/**
	 * Test method that guards the construction-time cipher of {@link KeyCommittingAeadEncryptor}
	 * against ever being handed out as {@code null} or as an uninitialised {@link Cipher}.
	 * <p>
	 * The positive half asserts that {@code getModel().getCipher()} is a real AES/GCM cipher that
	 * has been initialised with a fresh 96-bit nonce; the matching negative half asserts, on a
	 * freshly obtained cipher of the very same transformation, that an <em>uninitialised</em>
	 * AES/GCM cipher has no IV and cannot report an output size - which is what makes the positive
	 * assertions meaningful rather than vacuous.
	 * </p>
	 *
	 * @param testCase
	 *            the construction scenario
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@ParameterizedTest
	@MethodSource("constructionCases")
	void newCipher_publishesAnInitialisedAesGcmCipherOnTheModel(final ConstructionCase testCase)
		throws Exception
	{
		KeyCommittingAeadEncryptor encryptor = newEncryptor(testCase);

		Cipher constructionTimeCipher = encryptor.getModel().getCipher();
		assertNotNull(constructionTimeCipher,
			"newCipher(...) must hand back a cipher, the model must not end up with a null cipher");
		assertTrue(encryptor.getModel().isInitialized(),
			"onInitialize() must have flagged the model as initialized");
		assertEquals(MysticSymmetricAlgorithm.AES_GCM_NO_PADDING.getAlgorithm(),
			constructionTimeCipher.getAlgorithm(),
			"the construction-time cipher has to agree with the hardcoded AES-GCM of this class");

		byte[] nonce = constructionTimeCipher.getIV();
		assertNotNull(nonce,
			"the construction-time cipher must have been initialised - an initialised AES/GCM "
				+ "cipher reports the nonce it was initialised with");
		assertEquals(NONCE_LENGTH, nonce.length, "AES-GCM here uses a 96-bit nonce");
		assertEquals(GCM_TAG_LENGTH_BITS / Byte.SIZE, constructionTimeCipher.getOutputSize(0),
			"an ENCRYPT_MODE AES/GCM cipher turns zero input bytes into the 128-bit GCM tag");

		// the matching negative: the very same transformation, but never initialised, reports
		// neither a nonce nor an output size - so the assertions above really do observe init(...)
		Cipher neverInitialised = Cipher
			.getInstance(MysticSymmetricAlgorithm.AES_GCM_NO_PADDING.getAlgorithm());
		assertNull(neverInitialised.getIV(),
			"an uninitialised AES/GCM cipher has no nonce, so a non-null nonce above proves init(...) ran");
		assertThrows(IllegalStateException.class, () -> neverInitialised.getOutputSize(0),
			"an uninitialised AES/GCM cipher cannot report an output size");
	}

	/**
	 * Test method that guards the construction-time cipher against being unusable, by actually
	 * encrypting with it and decrypting the result with an independently built cipher that uses the
	 * same key and the nonce the construction-time cipher reports.
	 * <p>
	 * This pins down that {@code newCipher(...)} really returns a cipher that was initialised in
	 * {@link Cipher#ENCRYPT_MODE} with the model key and a usable nonce: a {@code null} return or a
	 * missing {@code init(...)} call makes {@code doFinal(...)} blow up instead of round-tripping.
	 * The matching negative half asserts that the same round trip fails when a different nonce is
	 * used, so the round trip really is bound to the nonce the cipher was initialised with.
	 * </p>
	 *
	 * @param testCase
	 *            the construction scenario
	 * @throws Exception
	 *             is thrown if an error occurs
	 */
	@ParameterizedTest
	@MethodSource("constructionCases")
	void newCipher_publishesACipherThatCanActuallyEncrypt(final ConstructionCase testCase)
		throws Exception
	{
		KeyCommittingAeadEncryptor encryptor = newEncryptor(testCase);
		byte[] plaintext = "the quick brown fox jumps over the lazy dog"
			.getBytes(StandardCharsets.UTF_8);

		Cipher constructionTimeCipher = encryptor.getModel().getCipher();
		byte[] nonce = constructionTimeCipher.getIV();
		byte[] ciphertext = constructionTimeCipher.doFinal(plaintext);

		assertNotEquals(0, ciphertext.length, "the cipher must have produced output");

		Cipher decryptCipher = Cipher
			.getInstance(MysticSymmetricAlgorithm.AES_GCM_NO_PADDING.getAlgorithm());
		decryptCipher.init(Cipher.DECRYPT_MODE, testKey,
			new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce));
		assertArrayEquals(plaintext, decryptCipher.doFinal(ciphertext),
			"the construction-time cipher must be a usable ENCRYPT_MODE AES/GCM cipher over the model key");

		// the matching negative: with any other nonce the same ciphertext must not authenticate
		byte[] otherNonce = nonce.clone();
		otherNonce[0] ^= (byte)0xFF;
		Cipher wrongNonceCipher = Cipher
			.getInstance(MysticSymmetricAlgorithm.AES_GCM_NO_PADDING.getAlgorithm());
		wrongNonceCipher.init(Cipher.DECRYPT_MODE, testKey,
			new GCMParameterSpec(GCM_TAG_LENGTH_BITS, otherNonce));
		assertThrows(Exception.class, () -> wrongNonceCipher.doFinal(ciphertext),
			"the ciphertext is bound to the nonce the construction-time cipher was initialised with");
	}
}
