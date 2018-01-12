package de.alpharogroup.crypto.factories;

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.security.PrivateKey;

import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link KeyPairFactory}.
 */
public class KeyPairFactoryTest {

	/**
	 * Test method for
	 * {@link KeyPairFactory#protectPrivateKeyWithPassword(PrivateKey, String)}
	 * and
	 * {@link KeyPairFactory#decryptPasswordProtectedPrivateKey(byte[], String, String)}
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testProtectPrivateKeyWithPassword() throws Exception {
		final File publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		final File privatekeyDerFile = new File(publickeyDerDir, "private.der");

		final PrivateKey privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);
		String password = "secret";
		final byte[] pwprotectedKey = KeyPairFactory.protectPrivateKeyWithPassword(privateKey, password);

		PrivateKey privKey = KeyPairFactory.decryptPasswordProtectedPrivateKey(pwprotectedKey, password, "RSA");
		assertEquals(privateKey, privKey);
	}

}
