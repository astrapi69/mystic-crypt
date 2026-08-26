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
package io.github.astrapi69.mystic.crypt.secret;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

import io.github.astrapi69.crypt.data.factory.ShamirSecretSharingFactory;

/**
 * Splits a secret into shares and puts it back together, on top of
 * {@link ShamirSecretSharingFactory}.
 * <p>
 * What this adds to the bare scheme is the part that makes it usable by hand: every share knows
 * which split it belongs to and how many shares that split needs, so {@link #combine(List)} can say
 * "this share is from a different split" and "this is fewer shares than the split needs" instead of
 * silently returning a wrong secret, which is what Shamir on its own does in both cases.
 */
public final class SecretSharing
{

	private SecretSharing()
	{
	}

	/**
	 * Splits the given secret into {@code shares} shares of which any {@code threshold} suffice to
	 * reconstruct it.
	 *
	 * @param secret
	 *            the secret to split
	 * @param threshold
	 *            the number of shares needed to reconstruct the secret
	 * @param shares
	 *            the number of shares to produce
	 * @return the shares, in index order
	 * @throws IllegalArgumentException
	 *             if the numbers do not describe a usable split
	 */
	public static List<SecretShare> split(final byte[] secret, final int threshold,
		final int shares)
	{
		requireUsableNumbers(threshold, shares);
		final SecureRandom random = new SecureRandom();
		final byte[] splitIdBytes = new byte[SecretShare.SPLIT_ID_LENGTH];
		random.nextBytes(splitIdBytes);
		final String splitId = HexFormat.of().formatHex(splitIdBytes);

		final List<ShamirSecretSharingFactory.Share> raw = ShamirSecretSharingFactory.split(secret,
			threshold, shares, random);
		final List<SecretShare> result = new ArrayList<>(raw.size());
		for (final ShamirSecretSharingFactory.Share share : raw)
		{
			result.add(
				new SecretShare(splitId, threshold, shares, share.getIndex(), share.getValue()));
		}
		return result;
	}

	/**
	 * Reconstructs the secret from the given shares.
	 *
	 * @param shares
	 *            the shares to combine, at least as many as the split's threshold
	 * @return the reconstructed secret
	 * @throws IllegalArgumentException
	 *             if the shares are empty, belong to more than one split, repeat an index, or are
	 *             fewer than the split needs
	 */
	public static byte[] combine(final List<SecretShare> shares)
	{
		if (shares == null || shares.isEmpty())
		{
			throw new IllegalArgumentException("no shares were given to combine");
		}
		final SecretShare first = shares.get(0);
		requireOneSplit(shares, first);
		requireDistinctIndices(shares);
		requireEnoughShares(shares, first);

		final List<ShamirSecretSharingFactory.Share> raw = new ArrayList<>(shares.size());
		for (final SecretShare share : shares)
		{
			raw.add(new ShamirSecretSharingFactory.Share(share.getIndex(), share.getValue()));
		}
		return ShamirSecretSharingFactory.combine(raw);
	}

	private static void requireUsableNumbers(final int threshold, final int shares)
	{
		if (threshold < 2)
		{
			throw new IllegalArgumentException("the threshold must be at least 2, but was "
				+ threshold + ": a split that one share alone can undo is not a split");
		}
		if (shares < threshold)
		{
			throw new IllegalArgumentException(
				"the number of shares (" + shares + ") must be at least the threshold (" + threshold
					+ "), otherwise the secret can never be reconstructed");
		}
	}

	private static void requireOneSplit(final List<SecretShare> shares, final SecretShare first)
	{
		for (final SecretShare share : shares)
		{
			if (!first.getSplitId().equals(share.getSplitId()))
			{
				throw new IllegalArgumentException("these shares belong to different splits: "
					+ first.getSplitId() + " and " + share.getSplitId()
					+ ". Combining them would rebuild nonsense rather than either secret");
			}
		}
	}

	private static void requireDistinctIndices(final List<SecretShare> shares)
	{
		final Set<Integer> seen = new HashSet<>();
		for (final SecretShare share : shares)
		{
			if (!seen.add(share.getIndex()))
			{
				throw new IllegalArgumentException("share " + share.getIndex()
					+ " was given more than once; the same share twice does not count twice");
			}
		}
	}

	private static void requireEnoughShares(final List<SecretShare> shares, final SecretShare first)
	{
		if (shares.size() < first.getThreshold())
		{
			throw new IllegalArgumentException(
				"this split needs " + first.getThreshold() + " shares, but " + shares.size()
					+ (shares.size() == 1 ? " was" : " were") + " given");
		}
	}
}
