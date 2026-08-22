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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.Key;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import javax.crypto.KEM;
import javax.crypto.KEMSpi;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.mystic.crypt.key.HybridKemKeyExchange.HybridEncapsulation;
import io.github.astrapi69.mystic.crypt.key.HybridKemKeyExchange.HybridKeyPair;
import io.github.astrapi69.mystic.crypt.key.HybridKemKeyExchange.HybridPrivateKey;
import io.github.astrapi69.mystic.crypt.key.HybridKemKeyExchange.HybridPublicKey;

/**
 * Mutation-focused tests for the secure wipe of the intermediate secret buffers of
 * {@link X25519KeyExchange} and {@link HybridKemKeyExchange}
 *
 * <p>
 * Both classes zero the raw key agreement respectively KEM secret in a {@code finally} block before
 * they return. Those buffers never reach the caller, so the wipe cannot be observed through the
 * return value - but the buffers do not belong to the exchange classes either. They are allocated
 * by whichever JCE provider serves {@code KeyAgreement.X25519} respectively {@code KEM.ML-KEM-768},
 * and that provider is free to keep a reference to them. That is precisely why the wipe exists, and
 * it is precisely where it can be observed: these tests install a provider that hands out - and
 * keeps - the secret buffers, then assert that they come back zeroed.
 *
 * <p>
 * Guards against a removed {@code Arrays.fill(...)} call in
 * {@link X25519KeyExchange#deriveSharedSecret(PrivateKey, PublicKey, int)},
 * {@link HybridKemKeyExchange#hybridEncapsulate(PublicKey, PublicKey, KeyPairGeneratorAlgorithm, int)}
 * and
 * {@link HybridKemKeyExchange#hybridDecapsulate(PrivateKey, PrivateKey, PublicKey, byte[], KeyPairGeneratorAlgorithm, int)}
 */
public class KeyExchangeSecretWipeTest
{

	/** The name of the provider that records the secret buffers it hands out */
	private static final String RECORDING_PROVIDER_NAME = "MysticCryptRecordingProvider";

	/** The length in bytes of the secret material the recording provider hands out */
	private static final int SECRET_LENGTH = 32;

	/** The length in bytes of the ciphertext the recording KEM hands out */
	private static final int ENCAPSULATION_LENGTH = 64;

	/** Every buffer the recording provider handed out since the last {@link #reset()} */
	private static final List<HandedOutBuffer> HANDED_OUT = new ArrayList<>();

	/**
	 * A buffer that the recording provider handed to the production code, together with a snapshot
	 * of its content taken at that very moment
	 *
	 * @param buffer
	 *            the array the production code received
	 * @param contentAtHandOut
	 *            a copy of the content the buffer carried when it was handed out
	 */
	record HandedOutBuffer(byte[] buffer, byte[] contentAtHandOut) {
	}

	/**
	 * The production call whose secure wipe is under test
	 */
	@FunctionalInterface
	interface WipeScenario
	{

		/**
		 * Runs the production call whose secure wipe is under test
		 *
		 * @throws Exception
		 *             is thrown if the production call fails
		 */
		void run() throws Exception;
	}

	/**
	 * A scenario with a production call that has to wipe every secret buffer it was handed
	 *
	 * @param description
	 *            the human readable description of the scenario
	 * @param recordingProvider
	 *            the provider that records the secret buffers it hands out
	 * @param scenario
	 *            the production call under test
	 * @param expectedBufferCount
	 *            the number of secret buffers the recording provider has to hand out during the
	 *            call
	 */
	record SecretWipeCase(String description, Provider recordingProvider, WipeScenario scenario,
		int expectedBufferCount) {
		@Override
		public String toString()
		{
			return description;
		}
	}

	static Stream<SecretWipeCase> secretWipeCases() throws Exception
	{
		HybridKeyPair recipient = HybridKemKeyExchange
			.newHybridKeyPair(KeyPairGeneratorAlgorithm.ML_KEM_768);
		HybridPublicKey recipientPublicKey = recipient.getHybridPublicKey();
		HybridPrivateKey recipientPrivateKey = recipient.getHybridPrivateKey();
		// a genuine encapsulation, produced before any recording provider is installed, so that the
		// decapsulation scenario that keeps the real ML-KEM has a ciphertext Bouncy Castle accepts
		HybridEncapsulation genuine = HybridKemKeyExchange.hybridEncapsulate(
			recipientPublicKey.getX25519PublicKey(), recipientPublicKey.getMlKemPublicKey(),
			KeyPairGeneratorAlgorithm.ML_KEM_768, 32);

		return Stream.of(
			new SecretWipeCase(
				"X25519KeyExchange.deriveSharedSecret wipes the raw agreement secret",
				new RecordingKeyAgreementProvider(),
				() -> X25519KeyExchange.deriveSharedSecret(
					recipientPrivateKey.getX25519PrivateKey(),
					recipientPublicKey.getX25519PublicKey(), 32),
				1),
			new SecretWipeCase(
				"HybridKemKeyExchange.hybridEncapsulate wipes the X25519 agreement secret",
				new RecordingKeyAgreementProvider(),
				() -> HybridKemKeyExchange.hybridEncapsulate(
					recipientPublicKey.getX25519PublicKey(), recipientPublicKey.getMlKemPublicKey(),
					KeyPairGeneratorAlgorithm.ML_KEM_768, 32),
				1),
			new SecretWipeCase(
				"HybridKemKeyExchange.hybridEncapsulate wipes the ML-KEM secret bytes",
				new RecordingKemProvider(),
				() -> HybridKemKeyExchange.hybridEncapsulate(
					recipientPublicKey.getX25519PublicKey(), recipientPublicKey.getMlKemPublicKey(),
					KeyPairGeneratorAlgorithm.ML_KEM_768, 32),
				1),
			new SecretWipeCase(
				"HybridKemKeyExchange.hybridDecapsulate wipes the X25519 agreement secret",
				new RecordingKeyAgreementProvider(),
				() -> HybridKemKeyExchange.hybridDecapsulate(
					recipientPrivateKey.getX25519PrivateKey(),
					recipientPrivateKey.getMlKemPrivateKey(), genuine.getSenderX25519PublicKey(),
					genuine.getMlKemCiphertext(), KeyPairGeneratorAlgorithm.ML_KEM_768, 32),
				1),
			new SecretWipeCase(
				"HybridKemKeyExchange.hybridDecapsulate wipes the ML-KEM secret bytes",
				new RecordingKemProvider(),
				() -> HybridKemKeyExchange.hybridDecapsulate(
					recipientPrivateKey.getX25519PrivateKey(),
					recipientPrivateKey.getMlKemPrivateKey(), genuine.getSenderX25519PublicKey(),
					new byte[ENCAPSULATION_LENGTH], KeyPairGeneratorAlgorithm.ML_KEM_768, 32),
				1));
	}

	/**
	 * Test method for the secure wipe of the intermediate secret buffers of
	 * {@link X25519KeyExchange} and {@link HybridKemKeyExchange}
	 *
	 * <p>
	 * Every buffer the recording provider handed to the production call has to be all zero once the
	 * call returned (the positive assertion), while the very same buffer must have carried non zero
	 * secret material when it was handed out (the matching negative assertion, without which the
	 * positive one would hold vacuously for a provider that never produced a secret at all).
	 *
	 * @param testCase
	 *            the test case
	 * @throws Exception
	 *             is thrown if the production call fails
	 */
	@ParameterizedTest
	@MethodSource("secretWipeCases")
	void everyIntermediateSecretBufferIsWipedBeforeTheCallReturns(final SecretWipeCase testCase)
		throws Exception
	{
		reset();
		Security.insertProviderAt(testCase.recordingProvider(), 1);
		try
		{
			testCase.scenario().run();
		}
		finally
		{
			Security.removeProvider(testCase.recordingProvider().getName());
		}
		List<HandedOutBuffer> handedOut = List.copyOf(HANDED_OUT);
		reset();

		assertEquals(testCase.expectedBufferCount(), handedOut.size(),
			"the recording provider has to hand out exactly the expected number of secret buffers, "
				+ "otherwise the wipe assertions would not cover the wiped buffer");
		for (HandedOutBuffer handedOutBuffer : handedOut)
		{
			assertFalse(isAllZero(handedOutBuffer.contentAtHandOut()),
				"the recording provider has to hand out non zero secret material, otherwise the "
					+ "wipe assertion would hold vacuously");
			assertTrue(isAllZero(handedOutBuffer.buffer()),
				"the intermediate secret buffer has to be wiped before the call returns");
		}
	}

	private static void reset()
	{
		HANDED_OUT.clear();
	}

	private static byte[] handOut(final byte[] buffer)
	{
		HANDED_OUT.add(new HandedOutBuffer(buffer, buffer.clone()));
		return buffer;
	}

	private static byte[] newSecretMaterial()
	{
		byte[] material = new byte[SECRET_LENGTH];
		for (int i = 0; i < material.length; i++)
		{
			// 1 .. 32, deliberately without a single zero byte, so that an all zero buffer after
			// the call can only be the work of the secure wipe
			material[i] = (byte)(i + 1);
		}
		return material;
	}

	private static boolean isAllZero(final byte[] buffer)
	{
		for (byte b : buffer)
		{
			if (b != 0)
			{
				return false;
			}
		}
		return true;
	}

	/**
	 * A {@link Provider} that serves {@code KeyAgreement.X25519} with an implementation that keeps
	 * a reference to every shared secret buffer it hands out
	 */
	static final class RecordingKeyAgreementProvider extends Provider
	{
		private static final long serialVersionUID = 1L;

		RecordingKeyAgreementProvider()
		{
			super(RECORDING_PROVIDER_NAME, "1.0",
				"records the X25519 shared secret buffers it hands out");
			putService(new Service(this, "KeyAgreement", "X25519",
				RecordingKeyAgreementSpi.class.getName(), null, null));
		}
	}

	/**
	 * A {@link KeyAgreementSpi} that hands out - and keeps a reference to - a fixed non zero shared
	 * secret
	 */
	public static final class RecordingKeyAgreementSpi extends KeyAgreementSpi
	{

		/**
		 * Instantiates a new {@link RecordingKeyAgreementSpi}, reflectively called by the JCE
		 */
		public RecordingKeyAgreementSpi()
		{
		}

		@Override
		protected void engineInit(final Key key, final SecureRandom random)
		{
		}

		@Override
		protected void engineInit(final Key key, final AlgorithmParameterSpec params,
			final SecureRandom random)
		{
		}

		@Override
		protected Key engineDoPhase(final Key key, final boolean lastPhase)
		{
			return null;
		}

		@Override
		protected byte[] engineGenerateSecret()
		{
			return handOut(newSecretMaterial());
		}

		@Override
		protected int engineGenerateSecret(final byte[] sharedSecret, final int offset)
		{
			throw new UnsupportedOperationException("not used by the classes under test");
		}

		@Override
		protected SecretKey engineGenerateSecret(final String algorithm)
		{
			throw new UnsupportedOperationException("not used by the classes under test");
		}
	}

	/**
	 * A {@link Provider} that serves {@code KEM.ML-KEM-768} with an implementation whose shared
	 * secret key keeps a reference to every buffer {@link SecretKey#getEncoded()} hands out
	 */
	static final class RecordingKemProvider extends Provider
	{
		private static final long serialVersionUID = 1L;

		RecordingKemProvider()
		{
			super(RECORDING_PROVIDER_NAME, "1.0",
				"records the ML-KEM shared secret buffers it hands out");
			putService(new Service(this, "KEM", KeyPairGeneratorAlgorithm.ML_KEM_768.getAlgorithm(),
				RecordingKemSpi.class.getName(), null, null));
		}
	}

	/**
	 * A {@link KEMSpi} whose encapsulation and decapsulation both produce a {@link SecretKey} that
	 * keeps a reference to every buffer {@link SecretKey#getEncoded()} hands out
	 */
	public static final class RecordingKemSpi implements KEMSpi
	{

		/**
		 * Instantiates a new {@link RecordingKemSpi}, reflectively called by the JCE
		 */
		public RecordingKemSpi()
		{
		}

		@Override
		public EncapsulatorSpi engineNewEncapsulator(final PublicKey publicKey,
			final AlgorithmParameterSpec spec, final SecureRandom secureRandom)
		{
			return new RecordingEncapsulatorSpi();
		}

		@Override
		public DecapsulatorSpi engineNewDecapsulator(final PrivateKey privateKey,
			final AlgorithmParameterSpec spec)
		{
			return new RecordingDecapsulatorSpi();
		}
	}

	private static final class RecordingEncapsulatorSpi implements KEMSpi.EncapsulatorSpi
	{

		@Override
		public KEM.Encapsulated engineEncapsulate(final int from, final int to,
			final String algorithm)
		{
			byte[] encapsulation = new byte[ENCAPSULATION_LENGTH];
			Arrays.fill(encapsulation, (byte)0x11);
			return new KEM.Encapsulated(new RecordingSecretKey(), encapsulation, null);
		}

		@Override
		public int engineSecretSize()
		{
			return SECRET_LENGTH;
		}

		@Override
		public int engineEncapsulationSize()
		{
			return ENCAPSULATION_LENGTH;
		}
	}

	private static final class RecordingDecapsulatorSpi implements KEMSpi.DecapsulatorSpi
	{

		@Override
		public SecretKey engineDecapsulate(final byte[] encapsulation, final int from, final int to,
			final String algorithm)
		{
			return new RecordingSecretKey();
		}

		@Override
		public int engineSecretSize()
		{
			return SECRET_LENGTH;
		}

		@Override
		public int engineEncapsulationSize()
		{
			return ENCAPSULATION_LENGTH;
		}
	}

	/**
	 * A {@link SecretKey} that returns a fresh copy of its key material on every
	 * {@link #getEncoded()} call - exactly as every well behaved implementation does - and keeps a
	 * reference to each copy it handed out
	 */
	private static final class RecordingSecretKey implements SecretKey
	{
		private static final long serialVersionUID = 1L;

		private final byte[] material = newSecretMaterial();

		@Override
		public String getAlgorithm()
		{
			return "Generic";
		}

		@Override
		public String getFormat()
		{
			return "RAW";
		}

		@Override
		public byte[] getEncoded()
		{
			return handOut(material.clone());
		}
	}
}
