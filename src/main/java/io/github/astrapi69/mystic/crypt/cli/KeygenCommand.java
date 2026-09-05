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

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.Callable;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.mystic.crypt.key.KeyFileWriter;
import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Generates a key pair for a chosen algorithm and prints, or writes to files, its private and
 * public key in PEM format.
 * <p>
 * Classical size-based algorithms (RSA, DSA) use {@code --size}; elliptic curve keys use
 * {@code --curve} to name the curve; the modern fixed-parameter algorithms (X25519/X448, ML-KEM,
 * ML-DSA, ...) need neither.
 */
@Command(name = "keygen", mixinStandardHelpOptions = true, //
	description = "Generate a key pair and print (or write) its keys as PEM. "
		+ "Exit code 0 = generated, 2 = error.")
public class KeygenCommand implements Callable<Integer>
{

	/**
	 * Instantiates a new {@link KeygenCommand}.
	 * <p>
	 * Declared explicitly, and public, because picocli builds this subcommand reflectively through
	 * its default factory when {@link MysticCryptCli} dispatches to it; the class must therefore
	 * keep an accessible no-argument constructor.
	 */
	public KeygenCommand()
	{
	}

	/** The private key encodings {@code --format} offers. */
	public enum Format
	{
		/** The wrapper that carries the key's algorithm inside the structure. */
		pkcs8,
		/** The traditional form, without that wrapper. */
		pkcs1
	}

	@Option(names = { "-a", "--algorithm" }, defaultValue = "RSA", //
		description = "Key algorithm, e.g. RSA, EC, X25519, X448, ML-KEM-768, ML-DSA-65 "
			+ "(dashes or underscores accepted; default: RSA).")
	String algorithm;

	@Option(names = { "-s", "--size" }, defaultValue = "2048", //
		description = "Key size in bits for size-based algorithms like RSA (default: 2048).")
	int size;

	@Option(names = { "-c", "--curve" }, //
		description = "The named curve for an EC key, e.g. secp256r1, secp384r1, secp521r1.")
	String curve;

	@Option(names = "--format", defaultValue = "pkcs8", //
		description = "The private key encoding: ${COMPLETION-CANDIDATES} (default: pkcs8).")
	Format format;

	@Option(names = "--print-details", description = "Say what was generated: the algorithm, the "
		+ "size or curve, and the encoding actually written.")
	boolean printDetails;

	@Option(names = "--out-private", description = "Write the private key PEM to this file instead of stdout.")
	File outPrivate;

	@Option(names = "--out-public", description = "Write the public key PEM to this file instead of stdout.")
	File outPublic;

	@Override
	public Integer call()
	{
		CliSupport.refuseDashAsPath(outPrivate, "--out-private", CliSupport.LEAVE_IT_OUT);
		CliSupport.refuseDashAsPath(outPublic, "--out-public", CliSupport.LEAVE_IT_OUT);
		try
		{
			KeyPair keyPair = generate();
			String privateKeyPem = writePrivateKey(keyPair.getPrivate());
			CliSupport.writePublicKeyPem(keyPair.getPublic(), outPublic);
			if (printDetails)
			{
				System.out.println(details(keyPair.getPrivate(), privateKeyPem));
			}
			return 0;
		}
		catch (Exception exception)
		{
			System.err.println(CliSupport.error(exception.getMessage()));
			return 2;
		}
	}

	private KeyPair generate() throws Exception
	{
		if (curve != null)
		{
			return newEcKeyPair();
		}
		KeyPairGeneratorAlgorithm keyPairAlgorithm = CliSupport.parseKeyPairAlgorithm(algorithm);
		return CliSupport.isSizeBased(keyPairAlgorithm)
			? KeyPairFactory.newKeyPair(keyPairAlgorithm, size)
			: KeyPairFactory.newKeyPair(keyPairAlgorithm);
	}

	/**
	 * Generates an elliptic curve key pair on the named curve, through Bouncy Castle so that the
	 * key can afterwards be used to sign with the same provider.
	 *
	 * @return the key pair
	 * @throws Exception
	 *             if the curve is unknown or the key cannot be generated
	 */
	private KeyPair newEcKeyPair() throws Exception
	{
		SecurityProviderSupport.ensureBouncyCastle();
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC",
			BouncyCastleProvider.PROVIDER_NAME);
		try
		{
			generator.initialize(new ECGenParameterSpec(curve));
		}
		catch (Exception unknownCurve)
		{
			throw new IllegalArgumentException(
				"unknown curve '" + curve
					+ "'. Use a named curve such as secp256r1, secp384r1 or secp521r1.",
				unknownCurve);
		}
		return generator.generateKeyPair();
	}

	/**
	 * Writes the private key in the requested encoding and returns what was written, so that the
	 * details line can report the encoding that really landed rather than the one asked for.
	 * <p>
	 * This does not go through the crypt-data writer, whose PKCS#8 option writes PKCS#1; see
	 * {@link KeyFileWriter}.
	 *
	 * @param privateKey
	 *            the private key
	 * @throws Exception
	 *             if the key cannot be written
	 */
	private String writePrivateKey(PrivateKey privateKey) throws Exception
	{
		String pem = KeyFileWriter.toPem(privateKey, format == Format.pkcs1);
		if (outPrivate == null)
		{
			System.out.print(pem);
			return pem;
		}
		// deliberately silent: with output files the existing contract is that nothing goes to
		// stdout, so a shell can redirect the printed form without a stray line in it
		Files.writeString(outPrivate.toPath(), pem, StandardCharsets.UTF_8);
		return pem;
	}

	/**
	 * Says what was generated. The encoding and the PEM label named here are read out of the PEM
	 * that was actually written, not out of the requested format, so a request for PKCS#1 that a
	 * key has no traditional form for is reported as the PKCS#8 it really became.
	 *
	 * @param privateKey
	 *            the generated private key
	 * @param privateKeyPem
	 *            the PEM that was written for that key
	 * @return the detail line
	 */
	private String details(PrivateKey privateKey, String privateKeyPem)
	{
		String label = labelOf(privateKeyPem);
		return "algorithm: " + privateKey.getAlgorithm() + ", " + sizeOrCurve(privateKey)
			+ ", private key format: "
			+ (KeyFileWriter.PKCS8_LABEL.equals(label) ? "PKCS#8" : "PKCS#1") + ", PEM label: "
			+ label;
	}

	private String sizeOrCurve(PrivateKey privateKey)
	{
		if (privateKey instanceof ECPrivateKey ecPrivateKey)
		{
			return "curve: " + (curve == null ? "unnamed" : curve) + ", field size: "
				+ ecPrivateKey.getParams().getCurve().getField().getFieldSize() + " bits";
		}
		if (privateKey instanceof RSAPrivateKey rsaPrivateKey)
		{
			return "size: " + rsaPrivateKey.getModulus().bitLength() + " bits";
		}
		if (privateKey instanceof DSAPrivateKey dsaPrivateKey)
		{
			return "size: " + dsaPrivateKey.getParams().getP().bitLength() + " bits";
		}
		return "fixed parameter set";
	}

	private static String labelOf(String privateKeyPem)
	{
		String firstLine = privateKeyPem.lines().findFirst().orElse("");
		return firstLine.replace("-----BEGIN ", "").replace("-----", "");
	}
}
