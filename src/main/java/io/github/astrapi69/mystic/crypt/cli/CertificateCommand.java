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
import java.util.concurrent.Callable;

import org.bouncycastle.asn1.x500.X500Name;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.factory.CertFactory;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.key.writer.CertificateWriter;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Generates a key pair and writes a self-signed X.509 v3 certificate for it in PEM format. Issuer
 * and subject are the same distinguished name (self-signed).
 */
@Command(name = "cert", mixinStandardHelpOptions = true, //
	description = "Create a self-signed X.509 certificate and write it as PEM.")
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

	@Override
	public Integer call() throws Exception
	{
		KeyPairGeneratorAlgorithm keyPairAlgorithm = CliSupport.parseKeyPairAlgorithm(algorithm);
		KeyPair keyPair = CliSupport.isSizeBased(keyPairAlgorithm)
			? KeyPairFactory.newKeyPair(keyPairAlgorithm, size)
			: KeyPairFactory.newKeyPair(keyPairAlgorithm);

		X500Name distinguishedName = new X500Name(subject);
		X509Certificate certificate = CertFactory.newX509CertificateV3(keyPair, distinguishedName,
			days, distinguishedName, signatureAlgorithm);
		CertificateWriter.writeInPemFormat(certificate, out);

		System.out.println("wrote self-signed certificate for '" + subject + "' to " + out);
		return 0;
	}
}
