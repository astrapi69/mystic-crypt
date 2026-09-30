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

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * One entry point for every signature suite the library provides, chosen by name at runtime:
 * Ed25519, the NIST post-quantum ML-DSA (FIPS 204) and SLH-DSA (FIPS 205), and the classical RSA,
 * EC (ECDSA) and DSA. Each post-quantum family and Ed25519 has its own signer and verifier class;
 * this class dispatches to them by the suite identifier, so a caller that learns the suite at
 * runtime - from a transaction, a file header, a command line option - does not write that switch
 * itself.
 * <p>
 * The identifiers are the ones the {@code sign} and {@code verify-signature} commands accept:
 * {@code Ed25519}, {@code ML-DSA-44}, {@code ML-DSA-65}, {@code ML-DSA-87}, an SLH-DSA parameter
 * set such as {@code SLH-DSA-SHA2-128S}, {@code RSA}, {@code EC} (or {@code ECDSA}), {@code DSA},
 * or a JCA signature name such as {@code SHA512withRSA}; case does not matter, and dashes and
 * underscores are interchangeable.
 * <p>
 * An identifier that names no suite is refused with an {@link IllegalArgumentException} on signing
 * and on verifying alike - it never verifies as {@code false}, so an unknown suite cannot be
 * mistaken for an invalid signature. SLH-DSA is not in the JDK as of 25; it is served here through
 * Bouncy Castle, which is one reason the dispatch belongs to the library rather than to each caller
 * (#149).
 */
public final class Signatures
{

	/** the name under which the Ed25519 signature family is offered */
	static final String ED25519 = "Ed25519";

	/**
	 * The classical families, mapped from the name a user gives to the JCA signature algorithm and
	 * the key factory algorithm that decodes their keys. {@code ECDSA} and {@code EC} name the same
	 * thing - a private key file reports one and a certificate the other - so both are accepted.
	 */
	private static final Map<String, Classical> CLASSICAL = Map.of(//
		"RSA", new Classical("SHA256withRSA", "RSA"), //
		"EC", new Classical("SHA256withECDSA", "EC"), //
		"ECDSA", new Classical("SHA256withECDSA", "EC"), //
		"DSA", new Classical("SHA256withDSA", "DSA"));

	/**
	 * One classical signature family.
	 *
	 * @param signatureAlgorithm
	 *            the JCA signature algorithm used when the user names only the key algorithm
	 * @param keyAlgorithm
	 *            the key factory algorithm that decodes keys of this family
	 */
	private record Classical(String signatureAlgorithm, String keyAlgorithm) {
	}

	private Signatures()
	{
	}

	/**
	 * Whether the given name selects one of the classical families, either by naming the key
	 * algorithm ({@code RSA}, {@code EC}, {@code ECDSA}, {@code DSA}) or by naming a JCA signature
	 * algorithm of one of them outright ({@code SHA512withRSA}).
	 *
	 * @param algorithm
	 *            the suite identifier
	 * @return true if this is a classical signature algorithm
	 */
	public static boolean isClassical(String algorithm)
	{
		return classicalOf(algorithm) != null;
	}

	private static Classical classicalOf(String algorithm)
	{
		Objects.requireNonNull(algorithm, "the signature suite must not be null");
		final String normalized = algorithm.trim().toUpperCase(Locale.ROOT);
		final Classical named = CLASSICAL.get(normalized);
		if (named != null)
		{
			return named;
		}
		final int with = normalized.indexOf("WITH");
		if (with < 0)
		{
			return null;
		}
		final Classical family = CLASSICAL.get(normalized.substring(with + "WITH".length()));
		return family == null ? null : new Classical(algorithm.trim(), family.keyAlgorithm());
	}

	/**
	 * Whether the given suite identifier selects the Ed25519 family.
	 *
	 * @param algorithm
	 *            the suite identifier
	 * @return true if this is Ed25519
	 */
	public static boolean isEd25519(String algorithm)
	{
		Objects.requireNonNull(algorithm, "the signature suite must not be null");
		return ED25519.equalsIgnoreCase(algorithm.trim());
	}

	/**
	 * The {@link java.security.KeyFactory} algorithm name that decodes keys of the given signature
	 * algorithm, e.g. for reading a PEM-encoded key.
	 *
	 * @param algorithm
	 *            the signature algorithm name
	 * @return the key factory algorithm name
	 * @throws IllegalArgumentException
	 *             if the name is not a supported signature algorithm
	 */
	public static String keyFactoryAlgorithm(String algorithm)
	{
		if (isEd25519(algorithm))
		{
			return ED25519;
		}
		Classical classical = classicalOf(algorithm);
		if (classical != null)
		{
			return classical.keyAlgorithm();
		}
		return parse(algorithm).getAlgorithm();
	}

	/**
	 * Signs the given bytes with the signer class of the algorithm's family.
	 *
	 * @param algorithm
	 *            the signature algorithm name
	 * @param privateKey
	 *            the signing key
	 * @param data
	 *            the bytes to sign
	 * @return the signature
	 * @throws IllegalArgumentException
	 *             if the name is not a supported signature algorithm
	 * @throws GeneralSecurityException
	 *             if signing fails, e.g. because the key does not belong to the suite
	 */
	public static byte[] sign(String algorithm, PrivateKey privateKey, byte[] data)
		throws GeneralSecurityException
	{
		if (isEd25519(algorithm))
		{
			return new Ed25519Signer(privateKey).sign(data);
		}
		Classical classical = classicalOf(algorithm);
		if (classical != null)
		{
			Signature signer = newClassicalSignature(classical);
			signer.initSign(privateKey);
			signer.update(data);
			return signer.sign();
		}
		KeyPairGeneratorAlgorithm parsed = parse(algorithm);
		return parsed.name().startsWith("ML_DSA")
			? new MlDsaSigner(privateKey, parsed).sign(data)
			: new SlhDsaSigner(privateKey, parsed).sign(data);
	}

	/**
	 * Verifies a signature over the given bytes with the verifier class of the algorithm's family.
	 *
	 * @param algorithm
	 *            the signature algorithm name
	 * @param publicKey
	 *            the verification key
	 * @param data
	 *            the signed bytes
	 * @param signature
	 *            the signature to check
	 * @return true if the signature belongs to the data and the key
	 * @throws IllegalArgumentException
	 *             if the name is not a supported signature algorithm - never answered with false
	 * @throws GeneralSecurityException
	 *             if verifying fails, e.g. because the key does not belong to the suite
	 */
	public static boolean verify(String algorithm, PublicKey publicKey, byte[] data,
		byte[] signature) throws GeneralSecurityException
	{
		if (isEd25519(algorithm))
		{
			return new Ed25519Verifier(publicKey).verify(data, signature);
		}
		Classical classical = classicalOf(algorithm);
		if (classical != null)
		{
			Signature verifier = newClassicalSignature(classical);
			verifier.initVerify(publicKey);
			verifier.update(data);
			return verifier.verify(signature);
		}
		KeyPairGeneratorAlgorithm parsed = parse(algorithm);
		return parsed.name().startsWith("ML_DSA")
			? new MlDsaVerifier(publicKey, parsed).verify(data, signature)
			: new SlhDsaVerifier(publicKey, parsed).verify(data, signature);
	}

	/**
	 * Builds the signature object for a classical family, naming Bouncy Castle explicitly.
	 * <p>
	 * The provider is not incidental. An elliptic-curve key on a named curve, as Bouncy Castle
	 * generates them, is rejected by the JDK's own SunEC provider when it signs ("Curve not
	 * supported"), and verification with such a key returns false rather than throwing - a valid
	 * signature then reads as an invalid one with nothing saying why. Signing, verifying and
	 * decoding all go through the same provider so that mismatch cannot arise.
	 */
	private static Signature newClassicalSignature(Classical classical)
		throws GeneralSecurityException
	{
		SecurityProviderSupport.ensureBouncyCastle();
		return Signature.getInstance(classical.signatureAlgorithm(),
			BouncyCastleProvider.PROVIDER_NAME);
	}

	/**
	 * Parses an ML-DSA or SLH-DSA algorithm name; everything else - unknown names and key-exchange
	 * algorithms that cannot sign at all - is refused with one message naming the value. Ed25519
	 * and the classical families never reach this method because its callers branch on them first.
	 */
	private static KeyPairGeneratorAlgorithm parse(String algorithm)
	{
		String constantName = algorithm.trim().toUpperCase(Locale.ROOT).replace('-', '_');
		for (KeyPairGeneratorAlgorithm candidate : KeyPairGeneratorAlgorithm.values())
		{
			if (candidate.name().equals(constantName) && (candidate.name().startsWith("ML_DSA")
				|| candidate.name().startsWith("SLH_DSA")))
			{
				return candidate;
			}
		}
		throw new IllegalArgumentException("'" + algorithm
			+ "' is not a supported signature algorithm. Use RSA, EC (or ECDSA), DSA, Ed25519, "
			+ "ML-DSA-44, ML-DSA-65, ML-DSA-87, an SLH-DSA parameter set such as "
			+ "SLH-DSA-SHA2-128S, or a JCA name such as SHA512withRSA.");
	}
}
