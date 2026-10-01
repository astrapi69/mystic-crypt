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

import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.util.Objects;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Additive blinding of Ed25519 keys (#166): from a public key {@code A} and a tweak {@code t}, the
 * public key {@code A + t*B}; from the private key, the matching expanded private key with scalar
 * {@code s + t mod l}. Both sides compute the same point, so whoever knows {@code A} and {@code t}
 * can compute where to pay, and only whoever holds {@code s} can spend from there.
 * <p>
 * This is the one-time key of stealth payments, as Monero derives it ({@code derive_public_key},
 * {@code derive_secret_key}) and as ERC-5564 does on secp256k1. The tweak comes from a shared
 * secret the payer and the payee both know; the payer, lacking {@code s}, can compute the
 * destination but not spend from it.
 * <p>
 * <b>This class contains curve arithmetic, which this library otherwise never writes</b>
 * (library-first.md, level 0). It exists because neither the JDK nor Bouncy Castle exposes Ed25519
 * point addition, and the maintainer decided for it in #166 knowing that rule. The group operations
 * themselves are Bouncy Castle's; see {@link Ed25519Points} for what is written here, and the
 * scalar arithmetic is not constant-time, see {@link Ed25519Scalars}.
 */
public final class Ed25519KeyBlinding
{

	private Ed25519KeyBlinding()
	{
	}

	/**
	 * Blinds a public key: {@code A + t*B}
	 *
	 * @param publicKey
	 *            the Ed25519 public key A
	 * @param tweak
	 *            the tweak t, read as a little-endian integer and reduced mod l; a whole 64-byte
	 *            hash is the best input
	 * @return the blinded public key
	 * @throws IllegalArgumentException
	 *             if the tweak is empty, or the key does not encode a point on the curve
	 */
	public static EdECPublicKey blind(final EdECPublicKey publicKey, final byte[] tweak)
	{
		Objects.requireNonNull(publicKey);
		ECPoint offset = Ed25519Points.BASE
			.multiply(Ed25519Scalars.tweakOf(Objects.requireNonNull(tweak)));
		ECPoint point = Ed25519Points.decode(Ed25519Points.encodedOf(publicKey));
		return Ed25519Points.publicKeyOf(point.add(offset));
	}

	/**
	 * Blinds a private key: the expanded key with scalar {@code s + t mod l}, whose public key is
	 * {@link #blind(EdECPublicKey, byte[])} of this key's public key and the same tweak
	 *
	 * @param privateKey
	 *            the Ed25519 private key; it has to carry its seed bytes
	 * @param tweak
	 *            the tweak t, as for the public key
	 * @return the blinded expanded private key, which signs with
	 *         {@link Ed25519ExpandedPrivateKey#sign(byte[])}
	 * @throws IllegalArgumentException
	 *             if the tweak is empty, or the key does not expose its seed
	 */
	public static Ed25519ExpandedPrivateKey blind(final EdECPrivateKey privateKey,
		final byte[] tweak)
	{
		return Ed25519ExpandedPrivateKey.of(privateKey).blind(tweak);
	}
}
