package de.alpharogroup.crypto.key.writer;

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;

import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.key.reader.EncryptedPrivateKeyReader;
import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link EncryptedPrivateKeyWriter}.
 */
public class EncryptedPrivateKeyWriterTest
{

	/**
	 * Test encrypt private key with password private key file string.
	 *
	 * @throws Exception is thrown if any error occurs on the execution
	 */
	@Test
	public void testEncryptPrivateKeyWithPasswordPrivateKeyFileString()  throws Exception
	{
		PrivateKey expected;
		PrivateKey actual;
		final File derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		final File encryptedPrivateKeyFile = new File(derDir, "encryptedPrivate.der");

		final PrivateKey readedPrivateKey = PrivateKeyReader
			.readPrivateKey(PathFinder.getSrcTestResourcesDir(), "der", "private.der");
		final String password = "secret";
		EncryptedPrivateKeyWriter.encryptPrivateKeyWithPassword(readedPrivateKey,
				encryptedPrivateKeyFile,
			password);

		final PrivateKey decryptedPrivateKey = EncryptedPrivateKeyReader.decryptPasswordProtectedPrivateKey(
				encryptedPrivateKeyFile, password, KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		expected = readedPrivateKey;
		actual = decryptedPrivateKey;
		assertEquals(expected, actual);
	}

}
