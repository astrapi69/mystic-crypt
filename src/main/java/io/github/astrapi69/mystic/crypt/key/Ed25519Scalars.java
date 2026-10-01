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

/**
 * Ed25519 scalars for {@link Ed25519KeyBlinding} (#166): integers modulo the order {@code l} of the
 * prime subgroup, in the little-endian byte order of RFC 8032.
 * <p>
 * The arithmetic is {@link BigInteger}, which is <b>not constant-time</b>. A blinded scalar is a
 * secret, so its timing is observable to whoever can measure this process; that is acceptable for
 * the joke chain this was written for (lethenon#21) and is the first thing to replace before
 * anything with real value depends on it.
 */
final class Ed25519Scalars
{

	/** The order of the prime subgroup, l = 2^252 + 27742317777372353535851937790883648493 */
	static final BigInteger L = BigInteger.TWO.pow(252)
		.add(new BigInteger("27742317777372353535851937790883648493"));

	private Ed25519Scalars()
	{
	}

	/**
	 * Reads a little-endian unsigned integer
	 *
	 * @param littleEndian
	 *            the bytes, lowest first
	 * @return the integer
	 */
	static BigInteger fromLittleEndian(final byte[] littleEndian)
	{
		byte[] bigEndian = new byte[littleEndian.length];
		for (int i = 0; i < littleEndian.length; i++)
		{
			bigEndian[i] = littleEndian[littleEndian.length - 1 - i];
		}
		return new BigInteger(1, bigEndian);
	}

	/**
	 * Writes a non-negative integer below 2^256 as 32 little-endian bytes
	 *
	 * @param value
	 *            the integer
	 * @return the 32 bytes, lowest first
	 */
	static byte[] toLittleEndian(final BigInteger value)
	{
		byte[] bigEndian = value.toByteArray();
		byte[] littleEndian = new byte[32];
		for (int i = 0; i < 32 && i < bigEndian.length; i++)
		{
			littleEndian[i] = bigEndian[bigEndian.length - 1 - i];
		}
		return littleEndian;
	}

	/**
	 * A tweak as a scalar: the bytes read as a little-endian integer, reduced mod l. Passing a
	 * whole 64-byte hash gives a scalar indistinguishable from uniform, which is how RFC 8032
	 * itself turns hashes into scalars.
	 *
	 * @param tweak
	 *            the bytes, at least one
	 * @return the scalar
	 * @throws IllegalArgumentException
	 *             if the tweak is empty
	 */
	static BigInteger tweakOf(final byte[] tweak)
	{
		if (tweak.length == 0)
		{
			throw new IllegalArgumentException(
				"an empty tweak blinds nothing; pass the hash the one-time key is derived from");
		}
		return fromLittleEndian(tweak).mod(L);
	}
}
