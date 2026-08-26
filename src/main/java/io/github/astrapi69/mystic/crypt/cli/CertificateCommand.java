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
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;

import org.bouncycastle.asn1.x500.X500Name;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.key.writer.CertificateWriter;
import io.github.astrapi69.mystic.crypt.ssl.SelfSignedCertificateFactory;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Generates a key pair and writes a self-signed X.509 v3 certificate for it in PEM format. Issuer
 * and subject are the same distinguished name (self-signed).
 */
@Command(name = "cert", mixinStandardHelpOptions = true, //
	description = "Create a self-signed X.509 certificate and write it as PEM, with basic "
		+ "constraints, key usage and subject alternative names. Exit code 0 = written, "
		+ "2 = error.")
public class CertificateCommand implements Callable<Integer>
{

	/**
	 * Instantiates a new {@link CertificateCommand}.
	 * <p>
	 * Declared explicitly, and public, because picocli builds this subcommand reflectively through
	 * its default factory when {@link MysticCryptCli} dispatches to it; the class must therefore
	 * keep an accessible no-argument constructor.
	 */
	public CertificateCommand()
	{
	}

	@Option(names = "--subject", defaultValue = "CN=mystic-crypt", //
		description = "The distinguished name for issuer and subject (default: CN=mystic-crypt).")
	String subject;

	@Option(names = { "-a", "--algorithm" }, defaultValue = "RSA", //
		description = "Key algorithm (default: RSA).")
	String algorithm;

	@Option(names = { "-s", "--size" }, defaultValue = "2048", //
		description = "Key size in bits for size-based algorithms like RSA (default: 2048).")
	int size;

	@Option(names = "--signature-algorithm", defaultValue = "SHA256withRSA", //
		description = "Certificate signature algorithm (default: SHA256withRSA).")
	String signatureAlgorithm;

	@Option(names = "--days", defaultValue = "365", //
		description = "Validity period in days from now (default: 365).")
	int days;

	@Option(names = "--out", required = true, description = "Write the certificate PEM to this file.")
	File out;

	@Option(names = "--basic-constraints", description = "Basic constraints: 'ca' or 'end-entity', "
		+ "optionally with a path length as in 'ca,pathlen=1'.")
	String basicConstraints;

	@Option(names = "--key-usage", split = ",", description = "Key usages, comma separated: "
		+ "digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, "
		+ "keyCertSign, cRLSign, encipherOnly, decipherOnly.")
	List<String> keyUsages = new ArrayList<>();

	@Option(names = "--san", description = "A subject alternative name as type:value, repeatable, "
		+ "e.g. dns:example.org, ip:10.0.0.1, email:someone@example.org, uri:https://example.org.")
	List<String> subjectAlternativeNames = new ArrayList<>();

	@Option(names = "--critical", split = ",", description = "Which of the extensions to mark "
		+ "critical, comma separated: basic-constraints, key-usage, san.")
	List<String> criticalExtensions = new ArrayList<>();

	@Override
	public Integer call()
	{
		try
		{
			KeyPairGeneratorAlgorithm keyPairAlgorithm = CliSupport
				.parseKeyPairAlgorithm(algorithm);
			KeyPair keyPair = CliSupport.isSizeBased(keyPairAlgorithm)
				? KeyPairFactory.newKeyPair(keyPairAlgorithm, size)
				: KeyPairFactory.newKeyPair(keyPairAlgorithm);

			X500Name distinguishedName = new X500Name(subject);
			X509Certificate certificate = SelfSignedCertificateFactory.create(keyPair,
				distinguishedName, days, signatureAlgorithm, extensions());
			CertificateWriter.writeInPemFormat(certificate, out);

			System.out.println("wrote self-signed certificate for '" + subject + "' to " + out
				+ describeExtensions());
			return 0;
		}
		catch (Exception exception)
		{
			System.err.println(CliSupport.error(exception.getMessage()));
			return 2;
		}
	}

	/**
	 * Builds the extension set from the options.
	 *
	 * @return the extensions to write
	 */
	private SelfSignedCertificateFactory.Extensions extensions()
	{
		List<SelfSignedCertificateFactory.SubjectAlternativeName> names = new ArrayList<>();
		for (String name : subjectAlternativeNames)
		{
			names.add(SelfSignedCertificateFactory.SubjectAlternativeName.parse(name));
		}
		return new SelfSignedCertificateFactory.Extensions(parseBasicConstraints(), keyUsages,
			names, criticalExtensions);
	}

	/**
	 * Parses {@code ca} or {@code end-entity}, optionally with {@code ,pathlen=n}.
	 *
	 * @return the parsed basic constraints, or null when the option was not given
	 */
	private SelfSignedCertificateFactory.BasicConstraintsSpec parseBasicConstraints()
	{
		if (basicConstraints == null)
		{
			return null;
		}
		String[] parts = basicConstraints.split(",");
		boolean certificateAuthority = switch (parts[0].trim().toLowerCase(Locale.ROOT))
		{
			case "ca" -> true;
			case "end-entity" -> false;
			default -> throw new IllegalArgumentException("basic constraints are either 'ca' or "
				+ "'end-entity', optionally with a path length as in 'ca,pathlen=1', but were '"
				+ basicConstraints + "'");
		};
		Integer pathLength = null;
		for (int i = 1; i < parts.length; i++)
		{
			String part = parts[i].trim();
			if (!part.toLowerCase(Locale.ROOT).startsWith("pathlen="))
			{
				throw new IllegalArgumentException("'" + part + "' is not part of basic "
					+ "constraints; only pathlen=<number> follows 'ca'");
			}
			pathLength = parsePathLength(part.substring("pathlen=".length()));
		}
		if (pathLength != null && !certificateAuthority)
		{
			throw new IllegalArgumentException("a path length only means something for a CA: an "
				+ "end entity signs no certificates, so there is no chain below it to limit");
		}
		return new SelfSignedCertificateFactory.BasicConstraintsSpec(certificateAuthority,
			pathLength);
	}

	private static Integer parsePathLength(String value)
	{
		try
		{
			int pathLength = Integer.parseInt(value);
			if (pathLength < 0)
			{
				throw new IllegalArgumentException(
					"a path length cannot be negative, but was " + pathLength);
			}
			return pathLength;
		}
		catch (NumberFormatException notANumber)
		{
			throw new IllegalArgumentException(
				"a path length must be a number, but was '" + value + "'", notANumber);
		}
	}

	/** Names the extensions that were written, so the run says what the certificate carries. */
	private String describeExtensions()
	{
		List<String> written = new ArrayList<>();
		if (basicConstraints != null)
		{
			written.add("basic constraints (" + basicConstraints + ")");
		}
		if (!keyUsages.isEmpty())
		{
			written.add("key usage (" + String.join(", ", keyUsages) + ")");
		}
		if (!subjectAlternativeNames.isEmpty())
		{
			written.add(
				"subject alternative names (" + String.join(", ", subjectAlternativeNames) + ")");
		}
		return written.isEmpty() ? "" : " with " + String.join(", ", written);
	}
}
