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
package io.github.astrapi69.mystic.crypt.srp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.lang.reflect.Field;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
import org.bouncycastle.crypto.util.DigestFactory;
import org.junit.jupiter.api.Test;

/**
 * Both {@link SRP6aClient#computeSessionKey(String, char[])} and
 * {@link SRP6aVerifierGenerator#generateVerifier(String, char[], byte[])} derive an internal
 * {@code byte[] passwordBytes} from the caller's {@code char[]} and wipe it in their
 * {@code finally} block. {@link SrpWipeAndProofTest} covers the wipe of the caller's own
 * {@code char[]}, which the caller still holds a reference to; the derived {@code byte[]} never
 * leaves the method, so nothing observed it and removing either {@code Arrays.fill} went unnoticed.
 *
 * <p>
 * These tests observe it through the collaborator that legitimately sees the buffer. Bouncy
 * Castle's {@code SRP6Util.calculateX} passes the array to {@code Digest.update(byte[], int, int)}
 * <em>by reference</em>, so a recording {@link Digest} keeps hold of the production array itself.
 * After the call returns, that array must read all zeroes.
 *
 * <p>
 * What this guards against: a session key or verifier derivation that leaves the UTF-8 encoded
 * password sitting in the heap after it is no longer needed, where a heap dump or a reused buffer
 * can still reach it.
 */
class SrpPasswordBytesWipeTest
{

	/** The password used throughout; its UTF-8 bytes are what the recorder looks for. */
	private static final String PASSWORD = "testPassword123";

	private static final String IDENTITY = "testuser";

	/**
	 * A {@link Digest} that behaves exactly like the SHA-256 the production code would have used,
	 * but keeps every array handed to {@link #update(byte[], int, int)} together with a snapshot of
	 * its contents at the time of the call.
	 */
	private static final class RecordingDigest implements Digest
	{
		private final Digest delegate = DigestFactory.createSHA256();

		/** the arrays as passed in, by reference */
		private final List<byte[]> seenArrays = new ArrayList<>();

		/** copies of those arrays, taken before the production code could wipe them */
		private final List<byte[]> snapshots = new ArrayList<>();

		@Override
		public String getAlgorithmName()
		{
			return delegate.getAlgorithmName();
		}

		@Override
		public int getDigestSize()
		{
			return delegate.getDigestSize();
		}

		@Override
		public void update(final byte in)
		{
			delegate.update(in);
		}

		@Override
		public void update(final byte[] in, final int inOff, final int len)
		{
			seenArrays.add(in);
			snapshots.add(Arrays.copyOfRange(in, inOff, inOff + len));
			delegate.update(in, inOff, len);
		}

		@Override
		public int doFinal(final byte[] out, final int outOff)
		{
			return delegate.doFinal(out, outOff);
		}

		@Override
		public void reset()
		{
			delegate.reset();
		}

		/**
		 * Finds the array whose contents, at the moment it was handed to the digest, were the UTF-8
		 * encoded password.
		 *
		 * @return the production array itself, or {@code null} if the password was never digested
		 */
		byte[] arrayThatHeldThePassword()
		{
			final byte[] expected = PASSWORD.getBytes(StandardCharsets.UTF_8);
			for (int i = 0; i < snapshots.size(); i++)
			{
				if (Arrays.equals(expected, snapshots.get(i)))
				{
					return seenArrays.get(i);
				}
			}
			return null;
		}
	}

	private static byte[] zeroesOfSameLength(final byte[] array)
	{
		return new byte[array.length];
	}

	/**
	 * Test method for {@link SRP6aClient#computeSessionKey(String, char[])}: the UTF-8 buffer it
	 * derives from the password must be zeroed before the method returns.
	 */
	@Test
	void computeSessionKeyWipesTheDerivedPasswordBytes() throws Exception
	{
		final SRP6aVerifierGenerator generator = new SRP6aVerifierGenerator();
		final byte[] salt = generator.generateSalt();
		final BigInteger verifier = generator.generateVerifier(IDENTITY, PASSWORD.toCharArray(),
			salt);

		final SRP6aServer server = new SRP6aServer();
		server.setVerifier(verifier);
		final SRP6aClient client = new SRP6aClient();
		final BigInteger clientPublicKey = client.generatePublicValue();
		final BigInteger serverPublicKey = server.generatePublicValue();
		client.setServerCredentials(salt, serverPublicKey);
		server.setClientPublicKey(clientPublicKey);

		// swap the client's own digest for one that records what it is asked to hash
		final RecordingDigest recorder = new RecordingDigest();
		final Field digestField = SRP6aClient.class.getDeclaredField("digest");
		digestField.setAccessible(true);
		digestField.set(client, recorder);

		client.computeSessionKey(IDENTITY, PASSWORD.toCharArray());

		final byte[] passwordBytes = recorder.arrayThatHeldThePassword();
		assertNotNull(passwordBytes,
			"the password was never handed to the digest - this test would pass vacuously");
		assertArrayEquals(zeroesOfSameLength(passwordBytes), passwordBytes,
			"computeSessionKey must wipe the UTF-8 password buffer it derived");
	}

	/**
	 * Test method for {@link SRP6aVerifierGenerator#generateVerifier(String, char[], byte[])}: the
	 * UTF-8 buffer it derives from the password must be zeroed before the method returns.
	 */
	@Test
	void generateVerifierWipesTheDerivedPasswordBytes() throws Exception
	{
		final SRP6aVerifierGenerator generator = new SRP6aVerifierGenerator();
		final byte[] salt = generator.generateSalt();

		// Bouncy Castle's SRP6VerifierGenerator exposes a public init(N, g, Digest), so the digest
		// can be replaced through its own API - only reading the field needs reflection.
		final RecordingDigest recorder = new RecordingDigest();
		final Field bcGeneratorField = SRP6aVerifierGenerator.class.getDeclaredField("bcGenerator");
		bcGeneratorField.setAccessible(true);
		final SRP6VerifierGenerator bcGenerator = (SRP6VerifierGenerator)bcGeneratorField
			.get(generator);
		bcGenerator.init(SRP6aVerifierGenerator.DEFAULT_N, SRP6aVerifierGenerator.DEFAULT_G,
			recorder);

		generator.generateVerifier(IDENTITY, PASSWORD.toCharArray(), salt);

		final byte[] passwordBytes = recorder.arrayThatHeldThePassword();
		assertNotNull(passwordBytes,
			"the password was never handed to the digest - this test would pass vacuously");
		assertArrayEquals(zeroesOfSameLength(passwordBytes), passwordBytes,
			"generateVerifier must wipe the UTF-8 password buffer it derived");
	}
}
