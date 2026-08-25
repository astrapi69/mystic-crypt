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
package io.github.astrapi69.mystic.crypt.cli;

import java.security.PrivateKey;
import java.security.PublicKey;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.mystic.crypt.key.Ed25519Signer;
import io.github.astrapi69.mystic.crypt.key.Ed25519Verifier;
import io.github.astrapi69.mystic.crypt.key.MlDsaSigner;
import io.github.astrapi69.mystic.crypt.key.MlDsaVerifier;
import io.github.astrapi69.mystic.crypt.key.SlhDsaSigner;
import io.github.astrapi69.mystic.crypt.key.SlhDsaVerifier;

/**
 * One entry point for the three signature families the library provides: the classical Ed25519 and
 * the NIST post-quantum ML-DSA (FIPS 204) and SLH-DSA (FIPS 205). Each family has its own signer
 * and verifier class, and Ed25519 differs from the other two in that its signer takes no algorithm
 * parameter. This class hides that split behind one string-keyed API, so the {@code sign} and
 * {@code verify-signature} subcommands can treat all of them alike.
 */
final class SignatureSupport
{

	/** the name under which the Ed25519 signature family is offered */
	static final String ED25519 = "Ed25519";

	private SignatureSupport()
	{
	}

	/** Whether the given algorithm name selects the Ed25519 family. */
	static boolean isEd25519(String algorithm)
	{
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
	static String keyFactoryAlgorithm(String algorithm)
	{
		if (isEd25519(algorithm))
		{
			return ED25519;
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
	 * @throws Exception
	 *             if signing fails
	 */
	static byte[] sign(String algorithm, PrivateKey privateKey, byte[] data) throws Exception
	{
		if (isEd25519(algorithm))
		{
			return new Ed25519Signer(privateKey).sign(data);
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
	 * @throws Exception
	 *             if verifying fails
	 */
	static boolean verify(String algorithm, PublicKey publicKey, byte[] data, byte[] signature)
		throws Exception
	{
		if (isEd25519(algorithm))
		{
			return new Ed25519Verifier(publicKey).verify(data, signature);
		}
		KeyPairGeneratorAlgorithm parsed = parse(algorithm);
		return parsed.name().startsWith("ML_DSA")
			? new MlDsaVerifier(publicKey, parsed).verify(data, signature)
			: new SlhDsaVerifier(publicKey, parsed).verify(data, signature);
	}

	/**
	 * Parses an ML-DSA or SLH-DSA algorithm name; everything else - including key-exchange
	 * algorithms that cannot sign at all - is rejected with a clear message. Ed25519 never reaches
	 * this method because its callers branch on {@link #isEd25519(String)} first.
	 */
	private static KeyPairGeneratorAlgorithm parse(String algorithm)
	{
		KeyPairGeneratorAlgorithm parsed = CliSupport.parseKeyPairAlgorithm(algorithm);
		if (!parsed.name().startsWith("ML_DSA") && !parsed.name().startsWith("SLH_DSA"))
		{
			throw new IllegalArgumentException("'" + algorithm
				+ "' is not a supported signature algorithm. Use Ed25519, ML-DSA-44, ML-DSA-65, "
				+ "ML-DSA-87 or an SLH-DSA parameter set such as SLH-DSA-SHA2-128S.");
		}
		return parsed;
	}
}
