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
package io.github.astrapi69.mystic.crypt.key.agreement;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.crypt.data.factory.SecretKeyFactoryExtensions;

public class TestKeyAgreement
{

	@Test
	public void testKeyAgreementWithDiffieHellman()
		throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException,
		NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		// Step 2: Generate Key Pairs for Both Parties
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
		keyPairGen.initialize(2048);
		KeyPair keyPairA = keyPairGen.generateKeyPair();
		KeyPair keyPairB = keyPairGen.generateKeyPair();
		// Step 3: Initialize KeyAgreement Objects
		KeyAgreement keyAgreeA = KeyAgreement.getInstance("DH");
		keyAgreeA.init(keyPairA.getPrivate());

		KeyAgreement keyAgreeB = KeyAgreement.getInstance("DH");
		keyAgreeB.init(keyPairB.getPrivate());
		// Step 4: Exchange Public Keys and Generate Shared Secret
		PublicKey publicKeyA = keyPairA.getPublic();
		PublicKey publicKeyB = keyPairB.getPublic();

		keyAgreeA.doPhase(publicKeyB, true);
		keyAgreeB.doPhase(publicKeyA, true);

		byte[] sharedSecretA = keyAgreeA.generateSecret();
		byte[] sharedSecretB = keyAgreeB.generateSecret();

		// Print Shared Secret (Base64 Encoded)
		System.out.println("Shared Secret A: " + Base64.getEncoder().encodeToString(sharedSecretA));
		System.out.println("Shared Secret B: " + Base64.getEncoder().encodeToString(sharedSecretB));

		String cipherAlgorithm = "DES/ECB/PKCS5Padding";
		String secretKeyAlgorithm = "DES";
		SecretKey aSecretKey = SecretKeyFactoryExtensions.newSecretKey(sharedSecretA,
			secretKeyAlgorithm);
		// encrypt a message...
		Cipher aCipher = Cipher.getInstance(cipherAlgorithm);
		aCipher.init(Cipher.ENCRYPT_MODE, aSecretKey);
		byte[] encryptedByteArray = aCipher
			.doFinal("Free your mind and get the best out of you".getBytes());
		SecretKeyFactory bSecretKeyFactory = SecretKeyFactory.getInstance(secretKeyAlgorithm);
		DESKeySpec bKeySpec = new DESKeySpec(sharedSecretB);
		SecretKey bSecretKey = bSecretKeyFactory.generateSecret(bKeySpec);

		Cipher bCipher = Cipher.getInstance(cipherAlgorithm);
		bCipher.init(Cipher.DECRYPT_MODE, bSecretKey);
		byte[] plaintext = bCipher.doFinal(encryptedByteArray);
		String text = new String(plaintext);
		System.out.println("Plain text:\n" + text);
	}

	@Test
	public void testKeyAgreementWithEllipticCurveDiffieHellman() throws NoSuchAlgorithmException,
		InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException,
		IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
	{
		// Step 2: Generate Key Pairs for Both Parties
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
		keyPairGen.initialize(new ECGenParameterSpec("secp256r1"));
		KeyPair keyPairA = keyPairGen.generateKeyPair();
		KeyPair keyPairB = keyPairGen.generateKeyPair();

		// Step 3: Initialize KeyAgreement Objects
		KeyAgreement keyAgreeA = KeyAgreement.getInstance("ECDH");
		keyAgreeA.init(keyPairA.getPrivate());

		KeyAgreement keyAgreeB = KeyAgreement.getInstance("ECDH");
		keyAgreeB.init(keyPairB.getPrivate());

		// Step 4: Exchange Public Keys and Generate Shared Secret
		PublicKey publicKeyA = keyPairA.getPublic();
		PublicKey publicKeyB = keyPairB.getPublic();

		keyAgreeA.doPhase(publicKeyB, true);
		keyAgreeB.doPhase(publicKeyA, true);

		byte[] sharedSecretA = keyAgreeA.generateSecret();
		byte[] sharedSecretB = keyAgreeB.generateSecret();

		// Print Shared Secret (Base64 Encoded)
		System.out.println("Shared Secret A: " + Base64.getEncoder().encodeToString(sharedSecretA));
		System.out.println("Shared Secret B: " + Base64.getEncoder().encodeToString(sharedSecretB));

		String cipherAlgorithm = "DES/ECB/PKCS5Padding";
		String secretKeyAlgorithm = "DES";
		SecretKey aSecretKey = SecretKeyFactoryExtensions.newSecretKey(sharedSecretA,
			secretKeyAlgorithm);
		// encrypt a message...
		Cipher aCipher = Cipher.getInstance(cipherAlgorithm);
		aCipher.init(Cipher.ENCRYPT_MODE, aSecretKey);
		byte[] encryptedByteArray = aCipher
			.doFinal("Free your mind and get the best out of you".getBytes());
		SecretKeyFactory bSecretKeyFactory = SecretKeyFactory.getInstance(secretKeyAlgorithm);
		DESKeySpec bKeySpec = new DESKeySpec(sharedSecretB);
		SecretKey bSecretKey = bSecretKeyFactory.generateSecret(bKeySpec);

		Cipher bCipher = Cipher.getInstance(cipherAlgorithm);
		bCipher.init(Cipher.DECRYPT_MODE, bSecretKey);
		byte[] plaintext = bCipher.doFinal(encryptedByteArray);
		String text = new String(plaintext);
		System.out.println("Plain text:\n" + text);

	}
}
