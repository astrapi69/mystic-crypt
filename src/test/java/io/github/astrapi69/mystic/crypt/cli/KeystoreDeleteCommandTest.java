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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
 * Unit tests for the {@code keystore delete} subcommand.
 */
class KeystoreDeleteCommandTest extends AbstractCliTest
{

	@BeforeAll
	static void registerBouncyCastle()
	{
		SecurityProviderSupport.ensureBouncyCastle();
	}

	/**
	 * Deleting one of two aliases must remove exactly that alias - and must write the store back in
	 * the very type it was opened with, for every supported store type.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "PKCS12", "JKS", "JCEKS" })
	void deletesExactlyTheGivenAliasAndKeepsTheStoreType(String type, @TempDir File tempDir)
		throws Exception
	{
		File storeFile = new File(tempDir, "store.ks");
		assertEquals(0, run("keystore", "create", "--file", storeFile.getAbsolutePath(), "--type",
			type, "--password", "secret"));
		assertEquals(0,
			run("keystore", "add-keypair", "--file", storeFile.getAbsolutePath(), "--type", type,
				"--password", "secret", "--alias", "doomed", "--dname", "CN=doomed", "--algorithm",
				"RSA"));
		assertEquals(0,
			run("keystore", "add-keypair", "--file", storeFile.getAbsolutePath(), "--type", type,
				"--password", "secret", "--alias", "survivor", "--dname", "CN=survivor",
				"--algorithm", "EC"));

		assertEquals(0, run("keystore", "delete", "--file", storeFile.getAbsolutePath(), "--type",
			type, "--password", "secret", "--alias", "doomed"));
		assertTrue(out.contains("deleted 'doomed'"),
			"stdout must confirm the deleted alias, but was: '" + out + "'");

		// the store must still load with its original type and hold only the surviving alias
		KeyStore keyStore = KeyStore.getInstance(type);
		try (InputStream inputStream = Files.newInputStream(storeFile.toPath()))
		{
			keyStore.load(inputStream, "secret".toCharArray());
		}
		assertFalse(keyStore.containsAlias("doomed"), "the deleted alias must be gone");
		assertTrue(keyStore.containsAlias("survivor"), "the other alias must survive");

		// KeyStore.getInstance("JKS") transparently loads PKCS12 files (DualFormatJKS), so the
		// reload above cannot prove the on-disk format; the file magic can
		byte[] header = new byte[4];
		try (InputStream inputStream = Files.newInputStream(storeFile.toPath()))
		{
			assertEquals(4, inputStream.read(header));
		}
		switch (type)
		{
			case "JKS" -> assertArrayEquals(
				new byte[] { (byte)0xFE, (byte)0xED, (byte)0xFE, (byte)0xED }, header,
				"a JKS store must keep the JKS file magic after delete");
			case "JCEKS" -> assertArrayEquals(
				new byte[] { (byte)0xCE, (byte)0xCE, (byte)0xCE, (byte)0xCE }, header,
				"a JCEKS store must keep the JCEKS file magic after delete");
			default -> assertEquals(0x30, header[0] & 0xFF,
				"a PKCS12 store must still start with an ASN.1 SEQUENCE after delete");
		}
	}

	@Test
	void anUnknownAliasFails(@TempDir File tempDir)
	{
		File storeFile = new File(tempDir, "store.ks");
		assertEquals(0, run("keystore", "create", "--file", storeFile.getAbsolutePath(),
			"--password", "secret"));
		assertNotEquals(0, run("keystore", "delete", "--file", storeFile.getAbsolutePath(),
			"--password", "secret", "--alias", "no-such"));
		assertTrue(err.contains("does not exist"),
			"the error must say the alias does not exist, but was: '" + err + "'");
	}
}
