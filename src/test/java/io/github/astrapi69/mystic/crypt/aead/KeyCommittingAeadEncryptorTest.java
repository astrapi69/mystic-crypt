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
package io.github.astrapi69.mystic.crypt.aead;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.data.model.CryptModel;

/**
 * Test class for {@link KeyCommittingAeadEncryptor}.
 *
 * @author Asterios Raptis
 * @since 10.5
 */
class KeyCommittingAeadEncryptorTest
{

	private SecretKey testKey;
	private KeyCommittingAeadEncryptor encryptor;

	@BeforeEach
	void setUp() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, UnsupportedEncodingException
	{
		// Generate a 256-bit AES key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		testKey = keyGen.generateKey();
		encryptor = new KeyCommittingAeadEncryptor(testKey);
	}

	@Test
	void testEncryptDecrypt() throws Exception
	{
		byte[] plaintext = "Hello, World!".getBytes();
		byte[] encrypted = encryptor.encrypt(plaintext);
		byte[] decrypted = encryptor.decrypt(encrypted);

		assertArrayEquals(plaintext, decrypted);
	}

	@Test
	void testEncryptDecryptWithAssociatedData() throws Exception
	{
		byte[] plaintext = "Hello, World!".getBytes();
		byte[] associatedData = "Additional authenticated data".getBytes();

		byte[] encrypted = encryptor.encrypt(plaintext, associatedData);
		byte[] decrypted = encryptor.decrypt(encrypted, associatedData);

		assertArrayEquals(plaintext, decrypted);
	}

	@Test
	void testEncryptDecryptNullAssociatedData() throws Exception
	{
		byte[] plaintext = "Hello, World!".getBytes();

		byte[] encrypted = encryptor.encrypt(plaintext, null);
		byte[] decrypted = encryptor.decrypt(encrypted, null);

		assertArrayEquals(plaintext, decrypted);
	}

	@Test
	void testEncryptDecryptEmptyAssociatedData() throws Exception
	{
		byte[] plaintext = "Hello, World!".getBytes();
		byte[] emptyAssociatedData = new byte[0];

		byte[] encrypted = encryptor.encrypt(plaintext, emptyAssociatedData);
		byte[] decrypted = encryptor.decrypt(encrypted, emptyAssociatedData);

		assertArrayEquals(plaintext, decrypted);
	}

	@Test
	void testEncryptedDataFormat() throws Exception
	{
		byte[] plaintext = "Test data".getBytes();
		byte[] encrypted = encryptor.encrypt(plaintext);

		// Format: IV (12 bytes) || Ciphertext || CommitmentTag (32 bytes)
		assertTrue(encrypted.length >= 12 + 32 + 1, "Encrypted data too short");
		assertEquals(12 + plaintext.length + 16 + 32, encrypted.length,
			"Expected: IV(12) + ciphertext(plaintext+GCM tag 16) + commitment(32)");
	}

	@Test
	void testDifferentPlaintextsProduceDifferentCiphertexts() throws Exception
	{
		byte[] plaintext1 = "First message".getBytes();
		byte[] plaintext2 = "Second message".getBytes();

		byte[] encrypted1 = encryptor.encrypt(plaintext1);
		byte[] encrypted2 = encryptor.encrypt(plaintext2);

		assertFalse(Arrays.equals(encrypted1, encrypted2));
	}

	@Test
	void testSamePlaintextProducesDifferentCiphertexts() throws Exception
	{
		byte[] plaintext = "Same message".getBytes();

		byte[] encrypted1 = encryptor.encrypt(plaintext);
		byte[] encrypted2 = encryptor.encrypt(plaintext);

		// Different random IVs should produce different ciphertexts
		assertFalse(Arrays.equals(encrypted1, encrypted2));
	}

	@Test
	void testWrongKeyFailsDecryption() throws Exception
	{
		byte[] plaintext = "Secret message".getBytes();
		byte[] encrypted = encryptor.encrypt(plaintext);

		// Generate a different key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		SecretKey wrongKey = keyGen.generateKey();
		KeyCommittingAeadEncryptor wrongEncryptor = new KeyCommittingAeadEncryptor(wrongKey);

		// Decryption should fail with wrong key
		assertThrows(Exception.class, () -> wrongEncryptor.decrypt(encrypted));
	}

	@Test
	void testTamperedCiphertextFailsDecryption() throws Exception
	{
		byte[] plaintext = "Important data".getBytes();
		byte[] encrypted = encryptor.encrypt(plaintext);

		// Tamper with the ciphertext (middle section)
		byte[] tampered = encrypted.clone();
		tampered[15] ^= 0xFF; // Flip bits in the ciphertext portion

		assertThrows(Exception.class, () -> encryptor.decrypt(tampered));
	}

	@Test
	void testTamperedIVFailsDecryption() throws Exception
	{
		byte[] plaintext = "Important data".getBytes();
		byte[] encrypted = encryptor.encrypt(plaintext);

		// Tamper with the IV (first 12 bytes)
		byte[] tampered = encrypted.clone();
		tampered[0] ^= 0xFF; // Flip bits in the IV

		// Should fail because commitment tag won't match
		assertThrows(SecurityException.class, () -> encryptor.decrypt(tampered));
	}

	@Test
	void testTamperedCommitmentTagFailsDecryption() throws Exception
	{
		byte[] plaintext = "Important data".getBytes();
		byte[] encrypted = encryptor.encrypt(plaintext);

		// Tamper with the commitment tag (last 32 bytes)
		byte[] tampered = encrypted.clone();
		int tagStart = encrypted.length - 32;
		tampered[tagStart] ^= 0xFF; // Flip bits in the commitment tag

		assertThrows(SecurityException.class, () -> encryptor.decrypt(tampered));
	}

	@Test
	void testWrongAssociatedDataFailsDecryption() throws Exception
	{
		byte[] plaintext = "Message with AD".getBytes();
		byte[] associatedData = "Original AD".getBytes();
		byte[] encrypted = encryptor.encrypt(plaintext, associatedData);

		// Try to decrypt with different associated data
		byte[] wrongAssociatedData = "Wrong AD".getBytes();
		assertThrows(SecurityException.class,
			() -> encryptor.decrypt(encrypted, wrongAssociatedData));
	}

	@Test
	void testMissingAssociatedDataFailsDecryption() throws Exception
	{
		byte[] plaintext = "Message with AD".getBytes();
		byte[] associatedData = "Original AD".getBytes();
		byte[] encrypted = encryptor.encrypt(plaintext, associatedData);

		// Try to decrypt without associated data
		assertThrows(SecurityException.class, () -> encryptor.decrypt(encrypted, null));
	}

	@Test
	void testKeyCommitmentProperty() throws Exception
	{
		// This test verifies that the same ciphertext cannot be decrypted
		// with a different key (key-committing property)

		byte[] plaintext = "Key-committing test".getBytes();
		byte[] encrypted = encryptor.encrypt(plaintext);

		// Generate multiple different keys and try to decrypt
		for (int i = 0; i < 5; i++)
		{
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(256);
			SecretKey differentKey = keyGen.generateKey();
			KeyCommittingAeadEncryptor differentEncryptor = new KeyCommittingAeadEncryptor(
				differentKey);

			// All should fail due to commitment verification
			assertThrows(SecurityException.class, () -> differentEncryptor.decrypt(encrypted),
				"Decryption should fail with key " + i);
		}
	}

	@Test
	void testMultipleEncryptDecryptCycles() throws Exception
	{
		byte[] plaintext = "Repeated test".getBytes();

		for (int i = 0; i < 10; i++)
		{
			byte[] encrypted = encryptor.encrypt(plaintext);
			byte[] decrypted = encryptor.decrypt(encrypted);
			assertArrayEquals(plaintext, decrypted);
		}
	}

	@Test
	void testLargeDataEncryption() throws Exception
	{
		byte[] largePlaintext = new byte[1024 * 1024]; // 1 MB
		Arrays.fill(largePlaintext, (byte)0x42);

		byte[] encrypted = encryptor.encrypt(largePlaintext);
		byte[] decrypted = encryptor.decrypt(encrypted);

		assertArrayEquals(largePlaintext, decrypted);
	}

	@Test
	void testConstructorWithCryptModel() throws Exception
	{
		CryptModel<Cipher, SecretKey, String> model = CryptModel
			.<Cipher, SecretKey, String> builder().key(testKey).build();
		KeyCommittingAeadEncryptor modelEncryptor = new KeyCommittingAeadEncryptor(model);

		byte[] plaintext = "Model test".getBytes();
		byte[] encrypted = modelEncryptor.encrypt(plaintext);
		byte[] decrypted = modelEncryptor.decrypt(encrypted);

		assertArrayEquals(plaintext, decrypted);
	}

	@Test
	void testEncryptedDataTooShort() throws Exception
	{
		byte[] tooShort = new byte[10]; // Less than minimum required
		assertThrows(IllegalArgumentException.class, () -> encryptor.decrypt(tooShort));
	}

	@Test
	void testZeroLengthPlaintext() throws Exception
	{
		byte[] emptyPlaintext = new byte[0];
		byte[] encrypted = encryptor.encrypt(emptyPlaintext);
		byte[] decrypted = encryptor.decrypt(encrypted);

		assertArrayEquals(emptyPlaintext, decrypted);
	}
}
