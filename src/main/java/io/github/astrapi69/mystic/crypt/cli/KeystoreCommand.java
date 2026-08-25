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
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.concurrent.Callable;

import org.bouncycastle.asn1.x500.X500Name;

import io.github.astrapi69.crypt.api.algorithm.HashAlgorithm;
import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.api.type.KeystoreType;
import io.github.astrapi69.crypt.data.factory.CertFactory;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.factory.KeyStoreFactory;
import io.github.astrapi69.crypt.data.key.CertificateExtensions;
import io.github.astrapi69.crypt.data.key.KeyStoreExtensions;
import io.github.astrapi69.crypt.data.key.reader.CertificateReader;
import io.github.astrapi69.crypt.data.key.writer.CertificateWriter;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

/**
 * Inspects and manages a Java key store from the command line: listing the entries, creating an
 * empty store, adding a freshly generated key pair with a self-signed certificate, importing and
 * exporting certificates and deleting an alias. Every subcommand works on a real key store file of
 * type PKCS12, JKS or JCEKS.
 */
@Command(name = "keystore", mixinStandardHelpOptions = true, //
	description = "Inspect and manage a Java key store (PKCS12, JKS or JCEKS).", //
	subcommands = { KeystoreCommand.ListCommand.class, KeystoreCommand.CreateCommand.class,
			KeystoreCommand.AddKeyPairCommand.class, KeystoreCommand.ImportCertificateCommand.class,
			KeystoreCommand.ExportCertificateCommand.class, KeystoreCommand.DeleteCommand.class })
public class KeystoreCommand implements Runnable
{

	/**
	 * Instantiates a new {@link KeystoreCommand}.
	 * <p>
	 * Declared explicitly, and public, because picocli builds this subcommand reflectively through
	 * its default factory when {@link MysticCryptCli} dispatches to it; the class must therefore
	 * keep an accessible no-argument constructor.
	 */
	public KeystoreCommand()
	{
	}

	@Override
	public void run()
	{
		// without a subcommand the usage is the most useful answer
		CommandLine.usage(this, System.out);
	}

	/**
	 * The signature algorithm that fits a key algorithm; a certificate can only be signed with a
	 * signature algorithm the key itself supports. Key-exchange algorithms such as X25519, X448 or
	 * the ML-KEM parameter sets cannot sign anything and are rejected here instead of being mapped
	 * silently to something else.
	 *
	 * @param algorithm
	 *            the key algorithm
	 * @return the matching certificate signature algorithm
	 * @throws IllegalArgumentException
	 *             if the algorithm cannot sign a certificate
	 */
	static String signatureAlgorithmFor(KeyPairGeneratorAlgorithm algorithm)
	{
		return switch (algorithm)
		{
			case RSA -> "SHA256withRSA";
			// an RSASSA-PSS key encodes with the id-RSASSA-PSS OID and per RFC 4055 must only
			// produce PSS signatures - a PKCS#1 v1.5 signature from such a key is rejected by
			// strict verifiers like OpenSSL
			case RSASSA_PSS -> "SHA256withRSAandMGF1";
			case EC -> "SHA256withECDSA";
			case DSA -> "SHA256withDSA";
			case ML_DSA_44 -> "ML-DSA-44";
			case ML_DSA_65 -> "ML-DSA-65";
			case ML_DSA_87 -> "ML-DSA-87";
			default -> throw new IllegalArgumentException("'" + algorithm
				+ "' cannot sign a certificate. Use RSA, RSASSA-PSS, EC, DSA, ML-DSA-44, "
				+ "ML-DSA-65 or ML-DSA-87.");
		};
	}

	/**
	 * Writes the key store back to its file. Deliberately not {@code KeyStoreExtensions.store(..)}
	 * or the {@code addAndStore*} helpers: those truncate the target in place, so a failed write
	 * would destroy every entry. This writes to a temporary file in the same directory first and
	 * moves it over the target atomically, so a failed write (full disk, killed process) cannot
	 * leave a truncated store behind. The store keeps the type it was opened with, whatever that
	 * is.
	 *
	 * @param keyStore
	 *            the key store to write
	 * @param file
	 *            the key store file
	 * @param password
	 *            the store password
	 * @throws Exception
	 *             if writing fails
	 */
	private static void store(KeyStore keyStore, File file, String password) throws Exception
	{
		File temp = File.createTempFile(file.getName() + ".", ".tmp",
			file.getAbsoluteFile().getParentFile());
		try (OutputStream outputStream = Files.newOutputStream(temp.toPath()))
		{
			keyStore.store(outputStream, password.toCharArray());
		}
		Files.move(temp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING,
			StandardCopyOption.ATOMIC_MOVE);
	}

	/**
	 * The options every keystore subcommand needs: which file, which store type and which password.
	 */
	static class StoreOptions
	{

		@Option(names = { "-f", "--file" }, required = true, description = "The key store file.")
		File file;

		@Option(names = { "-t", "--type" }, defaultValue = "PKCS12", //
			description = "The key store type: PKCS12, JKS or JCEKS (default: PKCS12).")
		KeystoreType type;

		@Option(names = { "-p", "--password" }, arity = "0..1", interactive = true, //
			description = "The key store password; asked for interactively when the value is left "
				+ "out. Prefer --password-stdin in scripts to keep it out of the process arguments.")
		String password;

		@Option(names = "--password-stdin", description = "Read the key store password from the first line of standard input.")
		boolean passwordStdin;

		/**
		 * the password once resolved; subcommands need it more than once and standard input can
		 * only be read once
		 */
		private String resolvedPassword;

		/**
		 * The store type to use, restricted to the file-based types this command supports; PKCS11
		 * and DKS need external hardware or a configuration file.
		 *
		 * @return the store type
		 * @throws IllegalArgumentException
		 *             if the type is not PKCS12, JKS or JCEKS
		 */
		KeystoreType type()
		{
			if (type != KeystoreType.PKCS12 && type != KeystoreType.JKS
				&& type != KeystoreType.JCEKS)
			{
				throw new IllegalArgumentException(
					"store type '" + type + "' is not supported. Use PKCS12, JKS or JCEKS.");
			}
			return type;
		}

		/**
		 * The resolved store password, from {@code --password} or standard input. Resolved only
		 * once: several subcommands use the password both for opening and for storing, and standard
		 * input yields the password only on the first read.
		 *
		 * @return the store password
		 */
		String password()
		{
			if (resolvedPassword == null)
			{
				resolvedPassword = CliSupport.resolvePassword(password, passwordStdin);
			}
			return resolvedPassword;
		}

		/**
		 * Opens the key store file with the resolved type and password.
		 *
		 * @return the loaded key store
		 * @throws Exception
		 *             if the file cannot be read or the password is wrong
		 */
		KeyStore open() throws Exception
		{
			return KeyStoreFactory.loadKeyStore(file, type().getType(), password());
		}
	}

	/** Lists what a key store holds, one line per alias, followed by the entry count. */
	@Command(name = "list", mixinStandardHelpOptions = true, //
		description = "List what a key store holds: alias, entry kind, algorithm, subject, "
			+ "validity end and SHA-256 fingerprint.")
	public static class ListCommand implements Callable<Integer>
	{

		/**
		 * Instantiates a new {@link ListCommand}.
		 * <p>
		 * Declared explicitly, and public, because picocli builds this subcommand reflectively
		 * through its default factory; the class must therefore keep an accessible no-argument
		 * constructor.
		 */
		public ListCommand()
		{
		}

		@Mixin
		StoreOptions store;

		@Override
		public Integer call() throws Exception
		{
			KeyStore keyStore = store.open();
			int count = 0;
			for (String alias : Collections.list(keyStore.aliases()))
			{
				Certificate certificate = keyStore.getCertificate(alias);
				// a key entry without any certificate is a symmetric secret key, not a private key
				String entryKind = keyStore.isKeyEntry(alias)
					? certificate != null ? "private key" : "secret key"
					: "certificate";
				String algorithm = "";
				String subject = "";
				String validUntil = "";
				String fingerprint = "";
				if (certificate instanceof X509Certificate x509)
				{
					algorithm = x509.getSigAlgName();
					subject = CertificateExtensions.getSubject(x509);
					validUntil = String.valueOf(x509.getNotAfter());
					fingerprint = CertificateExtensions.getFingerprint(x509, HashAlgorithm.SHA256);
				}
				System.out.println(alias + "\t" + entryKind + "\t" + algorithm + "\t" + subject
					+ "\t" + validUntil + "\t" + fingerprint);
				count++;
			}
			System.out.println(count + " entries");
			return 0;
		}
	}

	/** Creates a new, empty key store file. */
	@Command(name = "create", mixinStandardHelpOptions = true, //
		description = "Create a new, empty key store.")
	public static class CreateCommand implements Callable<Integer>
	{

		/**
		 * Instantiates a new {@link CreateCommand}.
		 * <p>
		 * Declared explicitly, and public, because picocli builds this subcommand reflectively
		 * through its default factory; the class must therefore keep an accessible no-argument
		 * constructor.
		 */
		public CreateCommand()
		{
		}

		@Mixin
		StoreOptions store;

		@Override
		public Integer call() throws Exception
		{
			if (store.file.exists())
			{
				throw new IllegalArgumentException(
					"'" + store.file + "' already exists; delete it first or choose another file.");
			}
			KeyStoreFactory.newKeyStore(store.file, store.type().getType(), store.password());
			System.out.println("created " + store.file);
			return 0;
		}
	}

	/**
	 * Generates a key pair, wraps its public key in a self-signed certificate and stores both under
	 * the given alias.
	 */
	@Command(name = "add-keypair", mixinStandardHelpOptions = true, //
		description = "Generate a key pair with a self-signed certificate and store it under an alias.")
	public static class AddKeyPairCommand implements Callable<Integer>
	{

		/**
		 * Instantiates a new {@link AddKeyPairCommand}.
		 * <p>
		 * Declared explicitly, and public, because picocli builds this subcommand reflectively
		 * through its default factory; the class must therefore keep an accessible no-argument
		 * constructor.
		 */
		public AddKeyPairCommand()
		{
		}

		@Mixin
		StoreOptions store;

		@Option(names = { "-a", "--alias" }, required = true, //
			description = "The alias to store the new entry under.")
		String alias;

		@Option(names = { "-d", "--dname" }, defaultValue = "CN=mystic-crypt", //
			description = "The certificate subject and issuer, for instance CN=my-server "
				+ "(default: CN=mystic-crypt).")
		String distinguishedName;

		@Option(names = { "-A", "--algorithm" }, defaultValue = "RSA", //
			description = "The key algorithm, e.g. RSA, EC, DSA or ML-DSA-65 "
				+ "(dashes or underscores accepted; default: RSA).")
		String algorithm;

		@Option(names = "--key-size", defaultValue = "2048", //
			description = "Key size in bits for size-based algorithms like RSA (default: 2048).")
		int keySize;

		@Option(names = "--days-valid", defaultValue = "365", //
			description = "Validity period of the self-signed certificate in days (default: 365).")
		int daysValid;

		@Spec
		CommandSpec spec;

		@Override
		public Integer call() throws Exception
		{
			KeyPairGeneratorAlgorithm keyAlgorithm = CliSupport.parseKeyPairAlgorithm(algorithm);
			String signatureAlgorithm = signatureAlgorithmFor(keyAlgorithm);
			if (spec.commandLine().getParseResult().hasMatchedOption("--key-size")
				&& !CliSupport.isSizeBased(keyAlgorithm))
			{
				throw new IllegalArgumentException(
					"--key-size only applies to the size-based " + "algorithms RSA, DSA and DH; '"
						+ keyAlgorithm + "' has a fixed parameter set.");
			}
			KeyStore keyStore = store.open();
			if (keyStore.containsAlias(alias))
			{
				throw new IllegalArgumentException("'" + alias + "' already exists in " + store.file
					+ "; delete it first or choose another alias.");
			}
			KeyPair keyPair = CliSupport.isSizeBased(keyAlgorithm)
				? KeyPairFactory.newKeyPair(keyAlgorithm, keySize)
				: KeyPairFactory.newKeyPair(keyAlgorithm);
			X500Name name = new X500Name(distinguishedName);
			X509Certificate certificate = CertFactory.newX509CertificateV3(keyPair, name, daysValid,
				name, signatureAlgorithm);
			keyStore.setKeyEntry(alias, keyPair.getPrivate(), store.password().toCharArray(),
				new Certificate[] { certificate });
			store(keyStore, store.file, store.password());
			System.out.println("added '" + alias + "' (" + keyAlgorithm + ")");
			return 0;
		}
	}

	/** Imports a certificate from a PEM or DER file and stores it under the given alias. */
	@Command(name = "import-cert", mixinStandardHelpOptions = true, //
		description = "Import a certificate from a PEM or DER file.")
	public static class ImportCertificateCommand implements Callable<Integer>
	{

		/**
		 * Instantiates a new {@link ImportCertificateCommand}.
		 * <p>
		 * Declared explicitly, and public, because picocli builds this subcommand reflectively
		 * through its default factory; the class must therefore keep an accessible no-argument
		 * constructor.
		 */
		public ImportCertificateCommand()
		{
		}

		@Mixin
		StoreOptions store;

		@Option(names = { "-a", "--alias" }, required = true, //
			description = "The alias to store the imported certificate under.")
		String alias;

		@Option(names = { "-c", "--certificate" }, required = true, //
			description = "The certificate file to import (PEM or DER).")
		File certificate;

		@Override
		public Integer call() throws Exception
		{
			KeyStore keyStore = store.open();
			if (keyStore.containsAlias(alias))
			{
				throw new IllegalArgumentException("'" + alias + "' already exists in " + store.file
					+ "; delete it first or choose another alias.");
			}
			X509Certificate imported = CertificateReader.readCertificate(certificate);
			keyStore.setCertificateEntry(alias, imported);
			store(keyStore, store.file, store.password());
			System.out.println("imported the certificate as '" + alias + "'");
			return 0;
		}
	}

	/** Writes the certificate stored under an alias as PEM. */
	@Command(name = "export-cert", mixinStandardHelpOptions = true, //
		description = "Write the certificate of an alias as PEM.")
	public static class ExportCertificateCommand implements Callable<Integer>
	{

		/**
		 * Instantiates a new {@link ExportCertificateCommand}.
		 * <p>
		 * Declared explicitly, and public, because picocli builds this subcommand reflectively
		 * through its default factory; the class must therefore keep an accessible no-argument
		 * constructor.
		 */
		public ExportCertificateCommand()
		{
		}

		@Mixin
		StoreOptions store;

		@Option(names = { "-a", "--alias" }, required = true, //
			description = "The alias whose certificate is exported.")
		String alias;

		@Option(names = { "-o", "--out" }, required = true, //
			description = "Write the certificate PEM to this file.")
		File out;

		@Override
		public Integer call() throws Exception
		{
			KeyStore keyStore = store.open();
			Certificate certificate = KeyStoreExtensions.getCertificate(keyStore, alias);
			if (!(certificate instanceof X509Certificate x509))
			{
				throw new IllegalArgumentException(
					"'" + alias + "' holds no X.509 certificate in " + store.file);
			}
			CertificateWriter.writeInPemFormat(x509, out);
			System.out.println("exported '" + alias + "' to " + out);
			return 0;
		}
	}

	/** Removes an alias from a key store file. */
	@Command(name = "delete", mixinStandardHelpOptions = true, //
		description = "Remove an alias from a key store.")
	public static class DeleteCommand implements Callable<Integer>
	{

		/**
		 * Instantiates a new {@link DeleteCommand}.
		 * <p>
		 * Declared explicitly, and public, because picocli builds this subcommand reflectively
		 * through its default factory; the class must therefore keep an accessible no-argument
		 * constructor.
		 */
		public DeleteCommand()
		{
		}

		@Mixin
		StoreOptions store;

		@Option(names = { "-a", "--alias" }, required = true, description = "The alias to remove.")
		String alias;

		@Override
		public Integer call() throws Exception
		{
			// deliberately not KeyStoreExtensions.deleteAlias: that loads the file as JKS
			// regardless of its real type and would write a PKCS12 store back in another format
			KeyStore keyStore = store.open();
			if (!keyStore.containsAlias(alias))
			{
				throw new IllegalArgumentException(
					"'" + alias + "' does not exist in " + store.file);
			}
			keyStore.deleteEntry(alias);
			store(keyStore, store.file, store.password());
			System.out.println("deleted '" + alias + "'");
			return 0;
		}
	}
}
