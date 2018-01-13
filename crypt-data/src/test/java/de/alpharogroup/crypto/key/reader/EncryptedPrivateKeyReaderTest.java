package de.alpharogroup.crypto.key.reader;

import static org.testng.AssertJUnit.assertEquals;

import java.security.PrivateKey;

import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.key.writer.PrivateKeyWriter;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link EncryptedPrivateKeyReader}.
 */
public class EncryptedPrivateKeyReaderTest
{

	/**
	 * Test method for {@link EncryptedPrivateKeyReader#decryptPasswordProtectedPrivateKey(byte[], String, String)}
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testDecryptPasswordProtectedPrivateKey() throws Exception
	{
		PrivateKey expected;
		PrivateKey actual;
		final PrivateKey readedPrivateKey = PrivateKeyReader
			.readPrivateKey(PathFinder.getSrcTestResourcesDir(), "der", "private.der");
		final String password = "secret";
		final byte[] pwprotectedKey = PrivateKeyWriter.encryptPrivateKeyWithPassword(readedPrivateKey,
			password);

		final PrivateKey decryptedPrivateKey = EncryptedPrivateKeyReader.decryptPasswordProtectedPrivateKey(
			pwprotectedKey, password, KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		expected = readedPrivateKey;
		actual = decryptedPrivateKey;
		assertEquals(expected, actual);
	}

}
