package de.alpharogroup.crypto.factories;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import de.alpharogroup.file.delete.DeleteFileExtensions;
import de.alpharogroup.file.search.PathFinder;

/**
 * Test class for the class {@link KeyStoreFactory}.
 */
public class KeyStoreFactoryTest {

	/**
	 * Test method for
	 * {@link KeyStoreFactory#newKeyStore(String, String, File, boolean)}. 
	 * 
	 * @throws NoSuchAlgorithmException
	 *             if the algorithm used to check the integrity of the keystore
	 *             cannot be found
	 * @throws CertificateException
	 *             if any of the certificates in the keystore could not be
	 *             loaded
	 * @throws FileNotFoundException
	 *             if the file not found
	 * @throws KeyStoreException
	 *             if the keystore has not been initialized (loaded).
	 * 
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	@Test
	public void testNewKeyStore() throws NoSuchAlgorithmException, CertificateException, FileNotFoundException,
			KeyStoreException, IOException {
		final File publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		final File privatekeyDerFile = new File(publickeyDerDir, "keystore.jks");

		KeyStore keystore = KeyStoreFactory.newKeyStore("jks", "foobar-secret-pw", privatekeyDerFile, true);
		AssertJUnit.assertNotNull(keystore);
		DeleteFileExtensions.delete(privatekeyDerFile);
	}

}
