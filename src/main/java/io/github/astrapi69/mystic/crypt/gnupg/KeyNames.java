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
package io.github.astrapi69.mystic.crypt.gnupg;

import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.ECPublicBCPGKey;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPUtil;

/**
 * Names a key's algorithm and use in the words gpg prints them, which is how the people who look at
 * this view know their keys: {@code rsa4096}, {@code ed25519}, {@code [SC]}
 */
final class KeyNames
{

	/**
	 * The curves gpg names differently from Bouncy Castle: the legacy OpenPGP encodings of Ed25519
	 * and Curve25519 gpg writes, and the NIST curves, which Bouncy Castle calls "NIST P-256" and
	 * gpg "nistp256". The brainpool curves and secp256k1 carry the same name in both
	 */
	private static final Map<String, String> GPG_CURVE_NAMES = Map.of("1.3.6.1.4.1.11591.15.1",
		"ed25519", "1.3.6.1.4.1.3029.1.5.1", "cv25519", "1.2.840.10045.3.1.7", "nistp256",
		"1.3.132.0.34", "nistp384", "1.3.132.0.35", "nistp521");

	private KeyNames()
	{
	}

	/**
	 * The algorithm of a key, with its size where the algorithm has one and its curve otherwise
	 *
	 * @param publicKey
	 *            the key
	 * @return for example {@code rsa2048} or {@code cv25519}
	 */
	static String algorithmOf(final PGPPublicKey publicKey)
	{
		BCPGKey key = publicKey.getPublicKeyPacket().getKey();
		if (key instanceof RSAPublicBCPGKey)
		{
			return "rsa" + publicKey.getBitStrength();
		}
		if (key instanceof ECPublicBCPGKey ellipticCurve)
		{
			return curveOf(ellipticCurve.getCurveOID());
		}
		return "algorithm " + publicKey.getAlgorithm();
	}

	private static String curveOf(final ASN1ObjectIdentifier curve)
	{
		String gpgName = GPG_CURVE_NAMES.get(curve.getId());
		if (gpgName != null)
		{
			return gpgName;
		}
		String name = PGPUtil.getCurveName(curve);
		return name != null ? name : curve.getId();
	}

	/**
	 * What a key is for, in gpg's letters and order
	 *
	 * @param keyFlags
	 *            the key flags of its latest self signature, null when it carries none
	 * @return for example {@code SC}, empty when the key states no use
	 */
	static String usageOf(final KeyFlags keyFlags)
	{
		if (keyFlags == null)
		{
			return "";
		}
		int flags = keyFlags.getFlags();
		StringBuilder usage = new StringBuilder();
		append(usage, flags, KeyFlags.SIGN_DATA, 'S');
		append(usage, flags, KeyFlags.CERTIFY_OTHER, 'C');
		append(usage, flags, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE, 'E');
		append(usage, flags, KeyFlags.AUTHENTICATION, 'A');
		return usage.toString();
	}

	private static void append(final StringBuilder usage, final int flags, final int mask,
		final char letter)
	{
		if ((flags & mask) != 0)
		{
			usage.append(letter);
		}
	}
}
