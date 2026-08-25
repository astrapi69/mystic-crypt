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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import io.github.astrapi69.mystic.crypt.provider.SecurityProviderSupport;

/**
 * Unit tests for the {@code keystore create} subcommand.
 */
class KeystoreCreateCommandTest extends AbstractCliTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	@ParameterizedTest
	@ValueSource(strings = { "PKCS12", "JKS", "JCEKS" })
	void createsAnEmptyStoreOfEveryFileBasedType(String type, @TempDir File tempDir)
		throws Exception
	{
		File storeFile = new File(tempDir, "store-" + type + ".ks");
		assertEquals(0, run("keystore", "create", "--file", storeFile.getAbsolutePath(), "--type",
			type, "--password", "secret"));
		assertTrue(out.contains("created " + storeFile.getAbsolutePath()),
			"stdout must confirm the created file, but was: '" + out + "'");

		// the file must be a real, loadable key store of the requested type
		KeyStore keyStore = KeyStore.getInstance(type);
		try (InputStream inputStream = Files.newInputStream(storeFile.toPath()))
		{
			keyStore.load(inputStream, "secret".toCharArray());
		}
		assertEquals(0, keyStore.size());
	}

	@Test
	void theStoreTypeDefaultsToPkcs12(@TempDir File tempDir) throws Exception
	{
		File storeFile = new File(tempDir, "default.ks");
		assertEquals(0, run("keystore", "create", "--file", storeFile.getAbsolutePath(),
			"--password", "secret"));

		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (InputStream inputStream = Files.newInputStream(storeFile.toPath()))
		{
			keyStore.load(inputStream, "secret".toCharArray());
		}
	}

	@Test
	void thePasswordCanComeFromStandardInput(@TempDir File tempDir) throws Exception
	{
		File storeFile = new File(tempDir, "stdin.ks");
		assertEquals(0, runWithStdin("secret\n", "keystore", "create", "--file",
			storeFile.getAbsolutePath(), "--password-stdin"));

		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (InputStream inputStream = Files.newInputStream(storeFile.toPath()))
		{
			keyStore.load(inputStream, "secret".toCharArray());
		}
	}

	@Test
	void anExistingFileIsNotOverwritten(@TempDir File tempDir) throws Exception
	{
		File storeFile = new File(tempDir, "existing.ks");
		Files.writeString(storeFile.toPath(), "do not overwrite me");
		assertNotEquals(0, run("keystore", "create", "--file", storeFile.getAbsolutePath(),
			"--password", "secret"));
		assertTrue(err.contains("already exists"),
			"the error must say the file already exists, but was: '" + err + "'");
		assertEquals("do not overwrite me", Files.readString(storeFile.toPath()),
			"the existing file must stay untouched");
	}

	/** PKCS11 and DKS need external hardware or a configuration file and are rejected. */
	@ParameterizedTest
	@ValueSource(strings = { "PKCS11", "DKS", "UNKNOWN" })
	void unsupportedStoreTypesAreRejected(String type, @TempDir File tempDir)
	{
		File storeFile = new File(tempDir, "unsupported.ks");
		assertNotEquals(0, run("keystore", "create", "--file", storeFile.getAbsolutePath(),
			"--type", type, "--password", "secret"));
		assertTrue(err.contains("is not supported"),
			"the error must name the unsupported type, but was: '" + err + "'");
	}

	@Test
	void anUnknownStoreTypeFailsAsUsageError(@TempDir File tempDir)
	{
		File storeFile = new File(tempDir, "unknown-type.ks");
		assertNotEquals(0, run("keystore", "create", "--file", storeFile.getAbsolutePath(),
			"--type", "NOPE", "--password", "secret"));
	}

	@Test
	void aMissingPasswordFails(@TempDir File tempDir)
	{
		File storeFile = new File(tempDir, "no-password.ks");
		assertNotEquals(0, run("keystore", "create", "--file", storeFile.getAbsolutePath()));
		assertTrue(err.contains("a password is required"),
			"the error must ask for a password, but was: '" + err + "'");
	}
}
