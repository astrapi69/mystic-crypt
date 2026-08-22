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
package io.github.astrapi69.mystic.crypt.cli;

import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.concurrent.Callable;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.mystic.crypt.key.HybridKemKeyExchange;
import io.github.astrapi69.mystic.crypt.key.HybridKemKeyExchange.HybridEncapsulation;
import io.github.astrapi69.mystic.crypt.key.HybridKemKeyExchange.HybridKeyPair;
import io.github.astrapi69.mystic.crypt.key.HybridKemKeyExchange.HybridPrivateKey;
import io.github.astrapi69.mystic.crypt.key.HybridKemKeyExchange.HybridPublicKey;
import io.github.astrapi69.mystic.crypt.key.MlKemKeyExchange;
import io.github.astrapi69.mystic.crypt.key.MlKemKeyExchange.Encapsulation;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Runs a two-party key-encapsulation exchange and shows that both sides derive the same shared
 * secret. Supports pure ML-KEM ({@code ML-KEM-512|768|1024}) and a hybrid X25519 + ML-KEM-768 mode.
 * Exit code 0 means the secrets matched.
 */
@Command(name = "kem", mixinStandardHelpOptions = true, //
	description = "Run a two-party ML-KEM or hybrid X25519+ML-KEM key encapsulation and show that "
		+ "both sides derive the same shared secret.")
public class KemCommand implements Callable<Integer>
{

	/** the hybrid derived key length in bytes (256-bit shared key) */
	private static final int HYBRID_SHARED_SECRET_BYTES = 32;

	@Option(names = { "-a", "--algorithm" }, defaultValue = "ML-KEM-768", //
		description = "ML-KEM-512, ML-KEM-768, ML-KEM-1024 or hybrid (default: ML-KEM-768).")
	String algorithm;

	@Override
	public Integer call() throws Exception
	{
		byte[] senderSecret;
		byte[] recipientSecret;
		byte[] ciphertext;

		if ("hybrid".equalsIgnoreCase(algorithm))
		{
			HybridKeyPair recipient = HybridKemKeyExchange
				.newHybridKeyPair(KeyPairGeneratorAlgorithm.ML_KEM_768);
			HybridPublicKey recipientPublicKey = recipient.getHybridPublicKey();
			HybridPrivateKey recipientPrivateKey = recipient.getHybridPrivateKey();

			HybridEncapsulation encapsulation = HybridKemKeyExchange.hybridEncapsulate(
				recipientPublicKey.getX25519PublicKey(), recipientPublicKey.getMlKemPublicKey(),
				KeyPairGeneratorAlgorithm.ML_KEM_768, HYBRID_SHARED_SECRET_BYTES);
			senderSecret = encapsulation.getSharedSecret().getEncoded();
			ciphertext = encapsulation.getMlKemCiphertext();
			recipientSecret = HybridKemKeyExchange.hybridDecapsulate(
				recipientPrivateKey.getX25519PrivateKey(), recipientPrivateKey.getMlKemPrivateKey(),
				encapsulation.getSenderX25519PublicKey(), encapsulation.getMlKemCiphertext(),
				KeyPairGeneratorAlgorithm.ML_KEM_768, HYBRID_SHARED_SECRET_BYTES).getEncoded();
		}
		else
		{
			KeyPairGeneratorAlgorithm mlKemAlgorithm = parseMlKem(algorithm);
			KeyPair recipient = MlKemKeyExchange.newKeyPair(mlKemAlgorithm);
			Encapsulation encapsulation = MlKemKeyExchange.encapsulate(recipient.getPublic(),
				mlKemAlgorithm);
			senderSecret = encapsulation.getSharedSecret().getEncoded();
			ciphertext = encapsulation.getCiphertext();
			recipientSecret = MlKemKeyExchange
				.decapsulate(recipient.getPrivate(), ciphertext, mlKemAlgorithm).getEncoded();
		}

		return report(algorithm, ciphertext, senderSecret, recipientSecret);
	}

	/**
	 * Prints the exchange result and returns the exit code (0 when the two shared secrets are
	 * equal, 1 otherwise). Separated from the crypto so the formatting and both outcomes are
	 * testable.
	 *
	 * @param algorithm
	 *            the algorithm label to print
	 * @param ciphertext
	 *            the ciphertext to print as hex
	 * @param senderSecret
	 *            the sender's derived shared secret
	 * @param recipientSecret
	 *            the recipient's derived shared secret
	 * @return 0 if the secrets match, otherwise 1
	 */
	static int report(String algorithm, byte[] ciphertext, byte[] senderSecret,
		byte[] recipientSecret)
	{
		boolean match = MessageDigest.isEqual(senderSecret, recipientSecret);
		System.out.println("algorithm: " + algorithm);
		System.out.println("ciphertext: " + CliSupport.HEX.formatHex(ciphertext));
		System.out.println("sender-secret: " + CliSupport.HEX.formatHex(senderSecret));
		System.out.println("recipient-secret: " + CliSupport.HEX.formatHex(recipientSecret));
		System.out.println(match ? "shared secrets match" : "shared secrets do not match");
		return match ? 0 : 1;
	}

	private static KeyPairGeneratorAlgorithm parseMlKem(String value)
	{
		switch (value.trim().toUpperCase().replace('-', '_'))
		{
			case "ML_KEM_512" :
				return KeyPairGeneratorAlgorithm.ML_KEM_512;
			case "ML_KEM_768" :
				return KeyPairGeneratorAlgorithm.ML_KEM_768;
			case "ML_KEM_1024" :
				return KeyPairGeneratorAlgorithm.ML_KEM_1024;
			default :
				throw new IllegalArgumentException("unknown KEM algorithm '" + value
					+ "'. Use ML-KEM-512, ML-KEM-768, ML-KEM-1024 or hybrid.");
		}
	}
}
