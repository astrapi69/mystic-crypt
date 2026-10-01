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

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.util.Arrays;
import java.util.Objects;

import io.github.astrapi69.crypt.api.algorithm.HashAlgorithm;

/**
 * An Ed25519 private key in expanded form: the secret scalar {@code s} and the 32-byte nonce prefix
 * of RFC 8032 section 5.1.5, which is what an Ed25519 seed is hashed into before signing (#166).
 * <p>
 * A blinded key exists only in this form. Its scalar is {@code s + t mod l}, and no seed hashes to
 * that, so neither the JDK nor Bouncy Castle can sign with it. {@link #sign(byte[])} implements RFC
 * 8032 section 5.1.6 over the expanded key, and the result is an ordinary Ed25519 signature: the
 * JDK's own {@code Signature.getInstance("Ed25519")} verifies it against {@link #publicKey()},
 * which is how the tests check it.
 * <p>
 * The scalar is held as a {@link BigInteger}, which can neither be wiped nor computed with in
 * constant time - see {@link Ed25519Scalars}.
 */
public final class Ed25519ExpandedPrivateKey
{

	/**
	 * Separates the derivation of a blinded nonce prefix from every other use of SHA-512 on the
	 * same prefix
	 */
	private static final byte[] PREFIX_DOMAIN = "mystic-crypt ed25519 blinded nonce prefix v1"
		.getBytes(StandardCharsets.US_ASCII);

	private final BigInteger scalar;

	private final byte[] prefix;

	private final byte[] publicKeyEncoded;

	private Ed25519ExpandedPrivateKey(final BigInteger scalar, final byte[] prefix)
	{
		this.scalar = scalar.mod(Ed25519Scalars.L);
		this.prefix = prefix.clone();
		this.publicKeyEncoded = Ed25519Points.encode(Ed25519Points.BASE.multiply(this.scalar));
	}

	/**
	 * The expanded form of an ordinary Ed25519 private key, RFC 8032 section 5.1.5: the seed is
	 * hashed with SHA-512, the lower half clamped into the scalar, the upper half kept as the nonce
	 * prefix. Signing with it gives exactly the signature the JDK gives for the same key.
	 *
	 * @param privateKey
	 *            the key; it has to carry its 32 seed bytes, as every key the JDK generates or
	 *            decodes does
	 * @return the expanded key
	 * @throws IllegalArgumentException
	 *             if the key does not expose its seed
	 */
	public static Ed25519ExpandedPrivateKey of(final EdECPrivateKey privateKey)
	{
		Objects.requireNonNull(privateKey);
		byte[] seed = privateKey.getBytes().orElseThrow(() -> new IllegalArgumentException(
			"the Ed25519 private key does not expose its seed bytes, so it cannot be expanded"));
		byte[] hash = sha512(seed);
		Arrays.fill(seed, (byte)0);
		byte[] clamped = Arrays.copyOf(hash, 32);
		clamped[0] &= (byte)248;
		clamped[31] &= 127;
		clamped[31] |= 64;
		Ed25519ExpandedPrivateKey expanded = new Ed25519ExpandedPrivateKey(
			Ed25519Scalars.fromLittleEndian(clamped), Arrays.copyOfRange(hash, 32, 64));
		Arrays.fill(clamped, (byte)0);
		Arrays.fill(hash, (byte)0);
		return expanded;
	}

	/**
	 * An expanded key from a raw scalar, for the known-answer tests that give scalars rather than
	 * seeds
	 */
	static Ed25519ExpandedPrivateKey ofScalar(final byte[] scalar, final byte[] prefix)
	{
		return new Ed25519ExpandedPrivateKey(Ed25519Scalars.fromLittleEndian(scalar), prefix);
	}

	/**
	 * Blinds this key additively: the scalar becomes {@code s + t mod l}, so the public key becomes
	 * {@code A + t*B}, the same point {@link Ed25519KeyBlinding#blind(EdECPublicKey, byte[])}
	 * computes from the public key alone. The nonce prefix is derived from this key's prefix and
	 * the tweak, so two blindings of one key never share a nonce.
	 *
	 * @param tweak
	 *            the tweak, read as a little-endian integer and reduced mod l; a whole 64-byte hash
	 *            is the best input
	 * @return the blinded key
	 * @throws IllegalArgumentException
	 *             if the tweak is empty
	 */
	public Ed25519ExpandedPrivateKey blind(final byte[] tweak)
	{
		BigInteger tweakScalar = Ed25519Scalars.tweakOf(Objects.requireNonNull(tweak));
		byte[] derivedPrefix = Arrays
			.copyOf(sha512(PREFIX_DOMAIN, prefix, Ed25519Scalars.toLittleEndian(tweakScalar)), 32);
		return new Ed25519ExpandedPrivateKey(scalar.add(tweakScalar), derivedPrefix);
	}

	/**
	 * The public key of this expanded key, {@code s*B}
	 *
	 * @return the public key
	 */
	public EdECPublicKey publicKey()
	{
		return Ed25519Points.publicKeyOf(Ed25519Points.decode(publicKeyEncoded));
	}

	/**
	 * Signs a message, RFC 8032 section 5.1.6, with this expanded key
	 *
	 * @param message
	 *            the message
	 * @return the 64-byte signature {@code R || S}
	 */
	public byte[] sign(final byte[] message)
	{
		Objects.requireNonNull(message);
		BigInteger nonce = Ed25519Scalars.fromLittleEndian(sha512(prefix, message))
			.mod(Ed25519Scalars.L);
		byte[] nonceEncoded = Ed25519Points.encode(Ed25519Points.BASE.multiply(nonce));
		BigInteger challenge = Ed25519Scalars
			.fromLittleEndian(sha512(nonceEncoded, publicKeyEncoded, message))
			.mod(Ed25519Scalars.L);
		BigInteger response = nonce.add(challenge.multiply(scalar)).mod(Ed25519Scalars.L);
		byte[] signature = Arrays.copyOf(nonceEncoded, 64);
		System.arraycopy(Ed25519Scalars.toLittleEndian(response), 0, signature, 32, 32);
		return signature;
	}

	/** The scalar, 32 bytes little-endian, for the known-answer tests */
	byte[] scalarBytes()
	{
		return Ed25519Scalars.toLittleEndian(scalar);
	}

	private static byte[] sha512(final byte[]... parts)
	{
		try
		{
			MessageDigest digest = MessageDigest.getInstance(HashAlgorithm.SHA_512.getAlgorithm());
			for (byte[] part : parts)
			{
				digest.update(part);
			}
			return digest.digest();
		}
		catch (NoSuchAlgorithmException exception)
		{
			// SHA-512 is one of the algorithms every Java platform is required to support
			throw new IllegalStateException("the JDK has no SHA-512", exception);
		}
	}
}
