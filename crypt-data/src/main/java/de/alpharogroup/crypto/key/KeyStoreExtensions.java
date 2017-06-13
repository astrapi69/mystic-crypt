package de.alpharogroup.crypto.key;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import de.alpharogroup.crypto.algorithm.KeystoreType;
import de.alpharogroup.crypto.factories.KeyStoreFactory;
import lombok.experimental.UtilityClass;

/**
 * The class {@link KeyStoreExtensions}.
 */
@UtilityClass
public class KeyStoreExtensions {

	/**
	 * Delete the given alias from the given keystore file.
	 *
	 * @param keystoreFile the keystore file
	 * @param alias the alias
	 * @param password the password
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws CertificateException the certificate exception
	 * @throws FileNotFoundException the file not found exception
	 * @throws KeyStoreException the key store exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public static void deleteAlias(final File keystoreFile, String alias, final String password) throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, KeyStoreException, IOException {
		KeyStore keyStore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), password, keystoreFile);
		keyStore.deleteEntry(alias);
		keyStore.store(new FileOutputStream(keystoreFile), password.toCharArray());
	}
	
}
