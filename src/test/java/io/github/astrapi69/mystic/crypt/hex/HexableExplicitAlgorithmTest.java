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
package io.github.astrapi69.mystic.crypt.hex;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.AesAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.Algorithm;
import io.github.astrapi69.mystic.crypt.algorithm.MysticSymmetricAlgorithm;
import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * The algorithm given to {@link HexableEncryptor#HexableEncryptor(String, Algorithm)} and
 * {@link HexableDecryptor#HexableDecryptor(String, Algorithm)} is the one they encrypt and decrypt
 * with (#210). Up to 13.8 it was set after the cipher had been built with the GCM default, so
 * {@code AesAlgorithm.AES} wrote GCM output without a nonce that nothing could read back. The
 * output is checked with plain JCE, not only against the decryptor, so that both sides being wrong
 * in the same way cannot pass.
 */
class HexableExplicitAlgorithmTest
{

	/** The 128-bit key of the report in #210 */
	private static final String KEY = "3C72139F8CF1B7A2";

	/** ChaCha20 takes 256-bit keys only */
	private static final String KEY_256 = "3C72139F8CF1B7A23C72139F8CF1B7A2";

	private static final String PLAINTEXT = "probe, with umlauts: äöü";

	private static final int NONCE_LENGTH = 12;

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	private static SecretKeySpec secretKey(final String key)
	{
		return new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
	}

	/** Plain JCE {@code "AES"} (ECB/PKCS5Padding), as mystic-crypt 7.x and any other tool wrote */
	private static String encryptWithPlainJceAes(final String plaintext) throws Exception
	{
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey(KEY));
		return HexFormat.of().formatHex(cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8)));
	}

	/**
	 * Reads what the encryptor wrote with plain JCE, nonce first where the transformation has one
	 */
	private static String decryptWithPlainJce(final Algorithm algorithm, final String key,
		final String hex) throws Exception
	{
		byte[] encrypted = HexFormat.of().parseHex(hex);
		String transformation = algorithm.getAlgorithm();
		Cipher cipher = Cipher.getInstance(transformation);
		if (algorithm == AesAlgorithm.AES)
		{
			cipher.init(Cipher.DECRYPT_MODE, secretKey(key));
			return new String(cipher.doFinal(encrypted), StandardCharsets.UTF_8);
		}
		byte[] nonce = Arrays.copyOfRange(encrypted, 0, NONCE_LENGTH);
		cipher.init(Cipher.DECRYPT_MODE, secretKey(key),
			algorithm == MysticSymmetricAlgorithm.AES_GCM_NO_PADDING
				? new GCMParameterSpec(128, nonce)
				: new IvParameterSpec(nonce));
		return new String(
			cipher.doFinal(Arrays.copyOfRange(encrypted, NONCE_LENGTH, encrypted.length)),
			StandardCharsets.UTF_8);
	}

	/**
	 * An explicit algorithm with a key it accepts
	 *
	 * @param algorithm
	 *            the algorithm given to the constructor
	 * @param key
	 *            the key
	 */
	record ExplicitAlgorithm(Algorithm algorithm, String key) {
		@Override
		public String toString()
		{
			return algorithm.getAlgorithm();
		}
	}

	static Stream<ExplicitAlgorithm> explicitAlgorithms()
	{
		return Stream.of(new ExplicitAlgorithm(AesAlgorithm.AES, KEY),
			new ExplicitAlgorithm(MysticSymmetricAlgorithm.AES_GCM_NO_PADDING, KEY),
			new ExplicitAlgorithm(MysticSymmetricAlgorithm.CHACHA20_POLY1305, KEY_256));
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("explicitAlgorithms")
	@DisplayName("the encryptor writes what plain JCE reads with the given algorithm")
	void encryptor_writesTheGivenAlgorithm(final ExplicitAlgorithm given) throws Exception
	{
		String hex = new HexableEncryptor(given.key(), given.algorithm()).encrypt(PLAINTEXT);

		assertEquals(PLAINTEXT, decryptWithPlainJce(given.algorithm(), given.key(), hex));
	}

	@ParameterizedTest(name = "{0}")
	@MethodSource("explicitAlgorithms")
	@DisplayName("encryptor and decryptor given the same algorithm round-trip")
	void encryptorAndDecryptor_roundTrip(final ExplicitAlgorithm given) throws Exception
	{
		String hex = new HexableEncryptor(given.key(), given.algorithm()).encrypt(PLAINTEXT);

		assertEquals(PLAINTEXT, new HexableDecryptor(given.key(), given.algorithm()).decrypt(hex));
	}

	@Test
	@DisplayName("the decryptor given AesAlgorithm.AES reads plain JCE AES, as written by 7.x")
	void decryptor_readsPlainJceAes() throws Exception
	{
		String legacyHex = encryptWithPlainJceAes(PLAINTEXT);

		assertEquals(PLAINTEXT, new HexableDecryptor(KEY, AesAlgorithm.AES).decrypt(legacyHex));
	}

	@Test
	@DisplayName("the key-only constructors still default to AES/GCM with a nonce")
	void keyOnlyConstructors_defaultToGcm() throws Exception
	{
		String hex = new HexableEncryptor(KEY).encrypt(PLAINTEXT);

		assertEquals(PLAINTEXT,
			decryptWithPlainJce(MysticSymmetricAlgorithm.AES_GCM_NO_PADDING, KEY, hex));
		assertEquals(PLAINTEXT, new HexableDecryptor(KEY).decrypt(hex));
	}

	@Test
	@DisplayName("a null algorithm is refused by both, naming the parameter")
	void nullAlgorithm_isRefused()
	{
		IllegalArgumentException encryptorRefusal = assertThrows(IllegalArgumentException.class,
			() -> new HexableEncryptor(KEY, null));
		IllegalArgumentException decryptorRefusal = assertThrows(IllegalArgumentException.class,
			() -> new HexableDecryptor(KEY, null));

		assertEquals(encryptorRefusal.getMessage(), decryptorRefusal.getMessage());
		assertTrue(encryptorRefusal.getMessage().contains("algorithm"),
			encryptorRefusal.getMessage());
	}
}
