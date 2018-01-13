package de.alpharogroup.crypto.factories;

import static org.testng.Assert.assertNotNull;

import java.io.File;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.crypto.key.reader.PublicKeyReader;
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
		final File publickeyDerFile = new File(publickeyDerDir, "public.der");
		final File privatekeyDerFile = new File(publickeyDerDir, "private.der");

		final PrivateKey privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		final PublicKey publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);

		final KeyPair keyPair = KeyPairFactory.newKeyPair(publicKey, privateKey);
		assertNotNull(keyPair);
	}

}
