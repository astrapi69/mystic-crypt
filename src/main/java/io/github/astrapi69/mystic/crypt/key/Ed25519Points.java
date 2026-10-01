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
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.HexFormat;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.djb.Curve25519;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;

/**
 * Ed25519 points for {@link Ed25519KeyBlinding} (#166), carried on Bouncy Castle's public
 * {@link Curve25519}.
 * <p>
 * Neither the JDK nor Bouncy Castle exposes point addition on the Edwards curve. Bouncy Castle does
 * expose Curve25519 in short Weierstrass form, with public addition and multiplication, and the
 * Edwards curve of Ed25519 is birationally equivalent to it (RFC 7748 section 4.1). So the only
 * curve code written here is that map and the point encoding of RFC 8032 section 5.1.2/5.1.3; every
 * group operation and every field operation, the square root included, is Bouncy Castle's.
 * <p>
 * The map, with {@code A = 486662} and {@code c} a square root of {@code -(A + 2)}:
 *
 * <pre>
 * Edwards (x, y)  ->  Montgomery u = (1 + y) / (1 - y), v = c * u / x
 *                 ->  Weierstrass X = u + A / 3,        Y = v
 * </pre>
 *
 * Either square root works, because choosing the other one composes the map with negation, which is
 * still an isomorphism - as long as both directions use the same {@code c}.
 */
final class Ed25519Points
{

	private static final Curve25519 CURVE = new Curve25519();

	private static final BigInteger P = CURVE.getQ();

	/** The Montgomery coefficient of Curve25519 */
	private static final ECFieldElement A = CURVE.fromBigInteger(BigInteger.valueOf(486662));

	/** A / 3, the shift between Montgomery u and Weierstrass X */
	private static final ECFieldElement A_THIRD = A
		.multiply(CURVE.fromBigInteger(BigInteger.valueOf(3)).invert());

	/** A square root of -(A + 2) = -486664 */
	private static final ECFieldElement C = CURVE
		.fromBigInteger(P.subtract(BigInteger.valueOf(486664))).sqrt();

	/** The Edwards coefficient d = -121665 / 121666 */
	private static final ECFieldElement D = CURVE
		.fromBigInteger(P.subtract(BigInteger.valueOf(121665)))
		.multiply(CURVE.fromBigInteger(BigInteger.valueOf(121666)).invert());

	private static final ECFieldElement ONE = CURVE.fromBigInteger(BigInteger.ONE);

	/** The RFC 8032 encoding of the base point B: y = 4/5, x even */
	private static final byte[] BASE_ENCODED = HexFormat.of()
		.parseHex("5866666666666666666666666666666666666666666666666666666666666666");

	/** The base point B in Weierstrass form */
	static final ECPoint BASE = decode(BASE_ENCODED);

	private Ed25519Points()
	{
	}

	/**
	 * Whether 32 bytes are the RFC 8032 encoding of a point on the curve
	 *
	 * @param encoded
	 *            the 32 bytes
	 * @return true if they decode
	 */
	static boolean isPoint(final byte[] encoded)
	{
		return decodeOrNull(encoded) != null;
	}

	/**
	 * Decodes 32 bytes, RFC 8032 section 5.1.3, into a point in Weierstrass form
	 *
	 * @param encoded
	 *            the 32 bytes
	 * @return the point
	 * @throws IllegalArgumentException
	 *             if the bytes are not the encoding of a point on the curve
	 */
	static ECPoint decode(final byte[] encoded)
	{
		ECPoint point = decodeOrNull(encoded);
		if (point == null)
		{
			throw new IllegalArgumentException(
				"not a point on Ed25519: " + HexFormat.of().formatHex(encoded));
		}
		return point;
	}

	private static ECPoint decodeOrNull(final byte[] encoded)
	{
		if (encoded.length != 32)
		{
			return null;
		}
		boolean xOdd = (encoded[31] & 0x80) != 0;
		byte[] yBytes = encoded.clone();
		yBytes[31] &= 0x7f;
		BigInteger yValue = Ed25519Scalars.fromLittleEndian(yBytes);
		if (yValue.compareTo(P) >= 0)
		{
			return null;
		}
		ECFieldElement y = CURVE.fromBigInteger(yValue);
		ECFieldElement ySquared = y.square();
		ECFieldElement xSquared = ySquared.subtract(ONE)
			.multiply(D.multiply(ySquared).add(ONE).invert());
		ECFieldElement x = xSquared.sqrt();
		if (x == null || (x.isZero() && xOdd))
		{
			return null;
		}
		if (x.testBitZero() != xOdd)
		{
			x = x.negate();
		}
		return toWeierstrass(x, y);
	}

	/**
	 * Encodes a point in Weierstrass form as 32 bytes, RFC 8032 section 5.1.2
	 *
	 * @param point
	 *            the point
	 * @return the 32 bytes
	 */
	static byte[] encode(final ECPoint point)
	{
		ECFieldElement[] edwards = toEdwards(point.normalize());
		byte[] encoded = Ed25519Scalars.toLittleEndian(edwards[1].toBigInteger());
		if (edwards[0].testBitZero())
		{
			encoded[31] |= (byte)0x80;
		}
		return encoded;
	}

	private static ECPoint toWeierstrass(final ECFieldElement x, final ECFieldElement y)
	{
		if (x.isZero())
		{
			// y = 1 is the neutral element, y = -1 the point of order two, (u, v) = (0, 0)
			return y.isOne()
				? CURVE.getInfinity()
				: CURVE.createPoint(A_THIRD.toBigInteger(), BigInteger.ZERO);
		}
		ECFieldElement u = ONE.add(y).multiply(ONE.subtract(y).invert());
		ECFieldElement v = C.multiply(u).multiply(x.invert());
		return CURVE.createPoint(u.add(A_THIRD).toBigInteger(), v.toBigInteger());
	}

	/**
	 * The inverse map. v = 0 happens only at (u, v) = (0, 0): u^2 + A u + 1 has no root in the
	 * field. u = -1, where the map has no image, does not happen at all: it would need A - 2 to be
	 * a square. Both are asserted by the tests rather than branched on here.
	 */
	private static ECFieldElement[] toEdwards(final ECPoint point)
	{
		if (point.isInfinity())
		{
			return new ECFieldElement[] { CURVE.fromBigInteger(BigInteger.ZERO), ONE };
		}
		ECFieldElement u = point.getAffineXCoord().subtract(A_THIRD);
		ECFieldElement v = point.getAffineYCoord();
		if (v.isZero())
		{
			return new ECFieldElement[] { v, ONE.negate() };
		}
		ECFieldElement x = C.multiply(u).multiply(v.invert());
		ECFieldElement y = u.subtract(ONE).multiply(u.add(ONE).invert());
		return new ECFieldElement[] { x, y };
	}

	/**
	 * The 32 encoded bytes of a JDK Ed25519 public key
	 *
	 * @param publicKey
	 *            the key
	 * @return the RFC 8032 encoding
	 */
	static byte[] encodedOf(final EdECPublicKey publicKey)
	{
		EdECPoint point = publicKey.getPoint();
		byte[] encoded = Ed25519Scalars.toLittleEndian(point.getY());
		if (point.isXOdd())
		{
			encoded[31] |= (byte)0x80;
		}
		return encoded;
	}

	/**
	 * A JDK Ed25519 public key for a point
	 *
	 * @param point
	 *            the point in Weierstrass form
	 * @return the key
	 */
	static EdECPublicKey publicKeyOf(final ECPoint point)
	{
		byte[] encoded = encode(point);
		boolean xOdd = (encoded[31] & 0x80) != 0;
		encoded[31] &= 0x7f;
		EdECPoint edecPoint = new EdECPoint(xOdd, Ed25519Scalars.fromLittleEndian(encoded));
		try
		{
			return (EdECPublicKey)KeyFactory
				.getInstance(KeyPairGeneratorAlgorithm.Ed25519.getAlgorithm())
				.generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, edecPoint));
		}
		catch (GeneralSecurityException exception)
		{
			// Ed25519 is part of every JDK since 15, and the point was just encoded from the curve
			throw new IllegalStateException("the JDK refused an Ed25519 public key", exception);
		}
	}
}
