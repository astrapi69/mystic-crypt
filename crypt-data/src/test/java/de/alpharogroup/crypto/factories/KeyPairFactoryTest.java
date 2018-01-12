package de.alpharogroup.crypto.factories;

import java.io.File;
import java.security.PrivateKey;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link KeyPairFactory}.
 */
public class KeyPairFactoryTest {

	/**
	 * Test method for {@link KeyPairFactory#newKeyPair(java.security.PublicKey, PrivateKey)}
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testProtectPrivateKeyWithPassword() throws Exception {
		final File publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		final File privatekeyDerFile = new File(publickeyDerDir, "private.der");

		Security.addProvider(new BouncyCastleProvider());

		final PrivateKey privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

	}

}
