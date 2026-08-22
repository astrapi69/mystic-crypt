/**
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
import java.nio.file.Files;
import java.security.KeyPair;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import io.github.astrapi69.crypt.api.algorithm.key.KeyPairGeneratorAlgorithm;
import io.github.astrapi69.crypt.data.factory.KeyPairFactory;
import io.github.astrapi69.crypt.data.key.writer.PrivateKeyWriter;

/**
 * Unit tests for the {@code der2pem} subcommand.
 */
class DerToPemCommandTest extends AbstractCliTest
{

	private File writeDerKey(File tempDir) throws Exception
	{
		KeyPair keyPair = KeyPairFactory.newKeyPair(KeyPairGeneratorAlgorithm.RSA, 2048);
		File derFile = new File(tempDir, "key.der");
		PrivateKeyWriter.write(keyPair.getPrivate(), derFile);
		return derFile;
	}

	@Test
	void convertsToPemOnStdout(@TempDir File tempDir) throws Exception
	{
		File derFile = writeDerKey(tempDir);
		assertEquals(0, run("der2pem", "--in", derFile.getAbsolutePath()));
		assertTrue(out.contains("PRIVATE KEY"));
	}

	@Test
	void convertsToPemFile(@TempDir File tempDir) throws Exception
	{
		File derFile = writeDerKey(tempDir);
		File pemFile = new File(tempDir, "key.pem");
		assertEquals(0,
			run("der2pem", "--in", derFile.getAbsolutePath(), "--out", pemFile.getAbsolutePath()));
		assertTrue(Files.readString(pemFile.toPath()).contains("PRIVATE KEY"));
	}

	@Test
	void invalidInputFails(@TempDir File tempDir) throws Exception
	{
		File notDer = new File(tempDir, "not-a-key.der");
		Files.writeString(notDer.toPath(), "definitely not a DER key");
		assertNotEquals(0, run("der2pem", "--in", notDer.getAbsolutePath()));
	}
}
