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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.util.Arrays;

import io.github.astrapi69.crypt.api.algorithm.MacAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.key.PrivateKeyExtensions;
import io.github.astrapi69.mystic.crypt.mac.HmacExtensions;

/**
 * Hierarchical key derivation from a seed after SLIP-0010, hardened only, for ed25519 and
 * curve25519 (#163).
 * <p>
 * One seed, many keys: every key is a path below the same master node, so the seed is the only
 * thing that has to be backed up. A derivation is a recovery format - a key restored in ten years
 * has to be the same key - which is why this follows a published standard with test vectors instead
 * of an own construction, and why it lives here, once, instead of in every consumer.
 * <p>
 * The only primitive is HMAC-SHA512 ({@link HmacExtensions}); there is no curve arithmetic, because
 * SLIP-0010 defines only hardened children for these two curves. Every index is therefore taken as
 * hardened and a path is given as plain numbers: {@code 44, 0, 0} is {@code m/44'/0'/0'}.
 *
 * @see <a href="https://github.com/satoshilabs/slips/blob/master/slip-0010.md">SLIP-0010</a>
 */
public final class SeedDerivation
{

	/** The shortest seed BIP-32 allows, 128 bits */
	public static final int SEED_MINIMUM = 16;

	/** The longest seed BIP-32 allows, 512 bits */
	public static final int SEED_MAXIMUM = 64;

	private static final int HARDENED = 0x8000_0000;

	private static final int HALF = 32;

	/**
	 * Which tree a key comes from. The name is the HMAC key of the master node, so the same seed
	 * gives unrelated keys on the two curves
	 */
	public enum Curve
	{
		/** signing keys, Ed25519 */
		ED25519("ed25519 seed", KeyPairGeneratorAlgorithm.Ed25519, NamedParameterSpec.ED25519),

		/** key agreement keys, X25519 */
		CURVE25519("curve25519 seed", KeyPairGeneratorAlgorithm.X25519, NamedParameterSpec.X25519);

		private final byte[] masterKey;

		private final KeyPairGeneratorAlgorithm algorithm;

		private final NamedParameterSpec parameters;

		Curve(final String masterKey, final KeyPairGeneratorAlgorithm algorithm,
			final NamedParameterSpec parameters)
		{
			this.masterKey = masterKey.getBytes(StandardCharsets.US_ASCII);
			this.algorithm = algorithm;
			this.parameters = parameters;
		}
	}

	/**
	 * A point in the tree: a private key and the chain code that derives its children. Both are
	 * handed out as copies, so no caller can change what another one reads.
	 */
	public static final class Node
	{

		private final byte[] privateKey;

		private final byte[] chainCode;

		private Node(final byte[] privateKey, final byte[] chainCode)
		{
			this.privateKey = privateKey;
			this.chainCode = chainCode;
		}

		/**
		 * The 32 bytes of the private key at this point
		 *
		 * @return a copy
		 */
		public byte[] privateKey()
		{
			return privateKey.clone();
		}

		/**
		 * The 32 bytes that, with the key, derive the children
		 *
		 * @return a copy
		 */
		public byte[] chainCode()
		{
			return chainCode.clone();
		}
	}

	private SeedDerivation()
	{
	}

	/**
	 * The node at a path below the master node of a seed
	 *
	 * @param curve
	 *            the tree
	 * @param seed
	 *            16 to 64 bytes
	 * @param path
	 *            the child indices, each one hardened; none means the master node
	 * @return the node
	 * @throws IllegalArgumentException
	 *             for a seed of the wrong length or a negative index
	 */
	public static Node derive(final Curve curve, final byte[] seed, final int... path)
	{
		if (seed.length < SEED_MINIMUM || seed.length > SEED_MAXIMUM)
		{
			throw new IllegalArgumentException("a seed is " + SEED_MINIMUM + " to " + SEED_MAXIMUM
				+ " bytes, and this one is " + seed.length + " bytes");
		}
		Node node = split(HmacExtensions.hmac(MacAlgorithm.HmacSHA512, curve.masterKey, seed));
		for (int index : path)
		{
			node = child(node, index);
		}
		return node;
	}

	/**
	 * The key pair at a path below the master node of a seed: Ed25519 on the ed25519 tree, X25519
	 * on the curve25519 tree
	 *
	 * @param curve
	 *            the tree
	 * @param seed
	 *            16 to 64 bytes
	 * @param path
	 *            the child indices, each one hardened
	 * @return the key pair
	 * @throws IllegalArgumentException
	 *             for a seed of the wrong length or a negative index
	 */
	public static KeyPair keyPairOf(final Curve curve, final byte[] seed, final int... path)
	{
		byte[] privateKeyBytes = derive(curve, seed, path).privateKey;
		KeySpec spec = curve == Curve.ED25519
			? new EdECPrivateKeySpec(curve.parameters, privateKeyBytes)
			: new XECPrivateKeySpec(curve.parameters, privateKeyBytes);
		try
		{
			PrivateKey privateKey = KeyFactory.getInstance(curve.algorithm.getAlgorithm())
				.generatePrivate(spec);
			return new KeyPair(PrivateKeyExtensions.generatePublicKey(privateKey), privateKey);
		}
		catch (GeneralSecurityException missing)
		{
			// both are part of every JDK since 15, and the key was just made from 32 bytes
			throw new IllegalStateException(
				"this Java runtime cannot make a " + curve.algorithm + " key pair", missing);
		}
		finally
		{
			Arrays.fill(privateKeyBytes, (byte)0);
		}
	}

	private static Node child(final Node parent, final int index)
	{
		if (index < 0)
		{
			throw new IllegalArgumentException("a child index counts from 0 to " + Integer.MAX_VALUE
				+ " and is hardened by the derivation itself, unlike " + index);
		}
		byte[] material = ByteBuffer.allocate(1 + HALF + Integer.BYTES).put((byte)0)
			.put(parent.privateKey).putInt(index | HARDENED).array();
		return split(HmacExtensions.hmac(MacAlgorithm.HmacSHA512, parent.chainCode, material));
	}

	private static Node split(final byte[] digest)
	{
		return new Node(Arrays.copyOfRange(digest, 0, HALF),
			Arrays.copyOfRange(digest, HALF, 2 * HALF));
	}
}
