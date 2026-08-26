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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.Callable;

import io.github.astrapi69.mystic.crypt.key.KeyFileDescription;
import io.github.astrapi69.mystic.crypt.key.KeyFileReader;
import io.github.astrapi69.mystic.crypt.key.KeyFileWriter;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * Examines a key or certificate file, says what it is, and converts it between the encodings that
 * make sense for it.
 * <p>
 * This replaces {@code der2pem}, which did one corner of the same job in one direction.
 */
@Command(name = "convert", mixinStandardHelpOptions = true, //
	description = "Say what a key or certificate file is, and convert it between PEM and DER or "
		+ "between PKCS#1 and PKCS#8. Exit code 0 = done, 2 = error.")
public class ConvertCommand implements Callable<Integer>
{

	/**
	 * Instantiates a new {@link ConvertCommand}.
	 * <p>
	 * Declared explicitly, and public, because picocli builds this subcommand reflectively through
	 * its default factory when {@link MysticCryptCli} dispatches to it; the class must therefore
	 * keep an accessible no-argument constructor.
	 */
	public ConvertCommand()
	{
	}

	/** The targets a file can be converted to. */
	public enum Target
	{
		/** Base64 between BEGIN and END lines. */
		pem,
		/** Raw DER bytes. */
		der,
		/** The traditional private key form, without the PKCS#8 wrapper. */
		pkcs1,
		/** The private key form that carries its algorithm in the structure. */
		pkcs8
	}

	@Option(names = { "-i",
			"--in" }, required = true, description = "The file to examine or convert.")
	File in;

	@Option(names = { "-o",
			"--out" }, description = "The file to write. Without it the result is printed, which "
				+ "only works for PEM.")
	File out;

	@Option(names = "--to", description = "What to convert to: ${COMPLETION-CANDIDATES}.")
	Target to;

	@Option(names = "--describe", description = "Only say what the file is, and convert nothing.")
	boolean describe;

	@Override
	public Integer call()
	{
		try
		{
			KeyFileDescription description = KeyFileDescription.of(in);
			System.out.println(in.getPath() + " is " + description.describe());
			if (describe || to == null)
			{
				if (!describe)
				{
					System.out.println("nothing was converted: pass --to to say what to convert it "
						+ "to, or --describe to ask only what it is");
				}
				return 0;
			}
			convert(description);
			return 0;
		}
		catch (Exception exception)
		{
			System.err.println(CliSupport.error(exception.getMessage()));
			return 2;
		}
	}

	/**
	 * One conversion result: either text to print or write, or bytes that only a file can hold.
	 *
	 * @param text
	 *            the PEM text, or null when the result is binary
	 * @param bytes
	 *            the DER bytes, or null when the result is text
	 * @param what
	 *            what was produced, for the confirmation line
	 */
	private record Converted(String text, byte[] bytes, String what) {

		static Converted text(String text, String what)
		{
			return new Converted(text, null, what);
		}

		static Converted bytes(byte[] bytes, String what)
		{
			return new Converted(null, bytes, what);
		}
	}

	private void convert(KeyFileDescription description) throws Exception
	{
		Converted converted = switch (description.content())
		{
			case CERTIFICATE -> convertCertificate(description);
			case PUBLIC_KEY -> convertPublicKey(description);
			case PRIVATE_KEY_PKCS1, PRIVATE_KEY_PKCS8 -> convertPrivateKey(description);
		};
		emit(converted);
	}

	private Converted convertPrivateKey(KeyFileDescription description) throws Exception
	{
		PrivateKey privateKey = KeyFileReader.readPrivateKey(in, description.algorithm());
		boolean wasPkcs1 = description.content() == KeyFileDescription.Content.PRIVATE_KEY_PKCS1;
		return switch (to)
		{
			case der -> Converted.bytes(KeyFileWriter.toPkcs8(privateKey), "DER, PKCS#8");
			case pkcs1 -> Converted.text(KeyFileWriter.toPem(privateKey, true), "PEM, PKCS#1");
			case pkcs8 -> Converted.text(KeyFileWriter.toPem(privateKey, false), "PEM, PKCS#8");
			// a private key asked for "pem" keeps the wrapping it already had, so that converting
			// only the encoding does not silently change the structure as well
			case pem -> Converted.text(KeyFileWriter.toPem(privateKey, wasPkcs1),
				"PEM, " + (wasPkcs1 ? "PKCS#1" : "PKCS#8"));
		};
	}

	private Converted convertPublicKey(KeyFileDescription description) throws Exception
	{
		PublicKey publicKey = KeyFileReader.readPublicKey(in, description.algorithm());
		return switch (to)
		{
			case der -> Converted.bytes(publicKey.getEncoded(), "DER");
			case pem -> Converted.text(KeyFileWriter.toPem(publicKey), "PEM");
			case pkcs1, pkcs8 -> throw new IllegalArgumentException(
				"PKCS#1 and PKCS#8 describe how "
					+ "a private key is wrapped; a public key has neither. Use --to pem or --to der.");
		};
	}

	private Converted convertCertificate(KeyFileDescription description) throws Exception
	{
		byte[] der = description.encoding() == KeyFileDescription.Encoding.DER
			? Files.readAllBytes(in.toPath())
			: certificateDerFromPem();
		return switch (to)
		{
			case der -> Converted.bytes(der, "DER");
			case pem -> Converted.text(KeyFileWriter.toPem("CERTIFICATE", der), "PEM");
			case pkcs1, pkcs8 -> throw new IllegalArgumentException(
				"PKCS#1 and PKCS#8 describe how "
					+ "a private key is wrapped; a certificate has neither. Use --to pem or --to der.");
		};
	}

	/**
	 * Writes or prints the result. DER is binary, so it can only go to a file.
	 *
	 * @param converted
	 *            what the conversion produced
	 * @throws Exception
	 *             if the file cannot be written
	 */
	private void emit(Converted converted) throws Exception
	{
		if (converted.text() == null)
		{
			if (out == null)
			{
				throw new IllegalArgumentException(
					"DER is binary and cannot be printed; pass --out to write it to a file");
			}
			Files.write(out.toPath(), converted.bytes());
		}
		else if (out == null)
		{
			System.out.print(converted.text());
			return;
		}
		else
		{
			Files.writeString(out.toPath(), converted.text(), StandardCharsets.UTF_8);
		}
		System.out.println("wrote " + converted.what() + " to " + out.getPath());
	}

	private byte[] certificateDerFromPem() throws Exception
	{
		try (org.bouncycastle.openssl.PEMParser parser = new org.bouncycastle.openssl.PEMParser(
			new java.io.FileReader(in, StandardCharsets.UTF_8)))
		{
			return ((org.bouncycastle.cert.X509CertificateHolder)parser.readObject()).getEncoded();
		}
	}

}
