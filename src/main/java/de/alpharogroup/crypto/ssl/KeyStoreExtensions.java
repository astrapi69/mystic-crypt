/**
 * The MIT License
 * <p>
 * Copyright (C) 2015 Asterios Raptis
 * <p>
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * <p>
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * <p>
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto.ssl;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import de.alpharogroup.crypto.algorithm.KeystoreType;
import de.alpharogroup.crypto.factories.KeyStoreFactory;

/**
 * The extension class {@link KeyStoreExtensions} provides extension methods for the
 * {@link KeyStore}
 */
public final class KeyStoreExtensions
{
	/**
	 * Add the given certificate to the given {@link KeyStore} object and stores it to the given
	 * keystore file
	 *
	 * @param keyStore
	 *            the keystore
	 * @param keystoreFile
	 *            the keystore file
	 * @param password
	 *            the password
	 * @param alias
	 *            the alias
	 * @param certificate
	 *            the certificate
	 * @throws KeyStoreException
	 *             is thrown if there is an error accessing the key store
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             is thrown if there is an error with an certificate
	 * @throws FileNotFoundException
	 *             is thrown if the keystore file not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void addAndStoreCertificate(final KeyStore keyStore, final File keystoreFile,
		final String password, String alias, Certificate certificate)
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		addCertificate(keyStore, alias, certificate);
		store(keyStore, keystoreFile, password);
	}

	/**
	 * Add the given private key to the given {@link KeyStore} object and stores it to the given
	 * keystore file
	 *
	 * @param keyStore
	 *            the keystore
	 * @param keystoreFile
	 *            the keystore file
	 * @param alias
	 *            the alias
	 * @param privateKey
	 *            the private key
	 * @param password
	 *            the password
	 * @param certificateChain
	 *            the certificate chain
	 * @throws KeyStoreException
	 *             is thrown if there is an error accessing the key store
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             is thrown if there is an error with an certificate
	 * @throws FileNotFoundException
	 *             is thrown if the keystore file not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void addAndStorePrivateKey(final KeyStore keyStore, final File keystoreFile,
		String alias, PrivateKey privateKey, char[] password, Certificate[] certificateChain)
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		addPrivateKey(keyStore, alias, privateKey, password, certificateChain);
		store(keyStore, keystoreFile, String.valueOf(password));
	}

	/**
	 * Add the given certificate to the given {@link KeyStore} object.
	 * <p>
	 * Note: it is added only to the {@link KeyStore} object. Do not forget to store the
	 * {@link KeyStore} object, for store it permanently to the keystore file.
	 *
	 * @param keyStore
	 *            the keystore
	 * @param alias
	 *            the alias
	 * @param certificate
	 *            the certificate
	 * @throws KeyStoreException
	 *             is thrown if there is an error accessing the key store
	 */
	public static void addCertificate(final KeyStore keyStore, String alias,
		Certificate certificate) throws KeyStoreException
	{
		keyStore.setCertificateEntry(alias, certificate);
	}

	/**
	 * Add the given private key to the given {@link KeyStore} object
	 * <p>
	 * Note: it is added only to the {@link KeyStore} object. Do not forget to store the
	 * {@link KeyStore} object, for store it permanently to the keystore file.
	 *
	 * @param keyStore
	 *            the keystore
	 * @param alias
	 *            the alias
	 * @param privateKey
	 *            the private key
	 * @param password
	 *            the password
	 * @param certificateChain
	 *            the certificate chain
	 * @throws KeyStoreException
	 *             is thrown if there is an error accessing the key store
	 */
	public static void addPrivateKey(final KeyStore keyStore, String alias, PrivateKey privateKey,
		char[] password, Certificate[] certificateChain) throws KeyStoreException
	{
		keyStore.setKeyEntry(alias, privateKey, password, certificateChain);
	}

	/**
	 * Delete the given alias from the given keystore file
	 *
	 * @param keystoreFile
	 *            the keystore file
	 * @param alias
	 *            the alias
	 * @param password
	 *            the password
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             is thrown if there is an error with an certificate
	 * @throws FileNotFoundException
	 *             is thrown if the keystore file not found
	 * @throws KeyStoreException
	 *             is thrown if there is an error accessing the key store
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void deleteAlias(final File keystoreFile, String alias, final String password)
		throws NoSuchAlgorithmException, CertificateException, FileNotFoundException,
		KeyStoreException, IOException
	{
		KeyStore keyStore = KeyStoreFactory.loadKeyStore(keystoreFile, KeystoreType.JKS.name(),
			password);

		keyStore.deleteEntry(alias);
		store(keyStore, keystoreFile, password);
	}

	/**
	 * Gets the certificate that is associated with the given alias from the given {@link KeyStore}
	 * object
	 *
	 * @param keyStore
	 *            the keystore
	 * @param alias
	 *            the alias
	 * @return the certificate
	 * @throws KeyStoreException
	 *             is thrown if there is an error accessing the key store
	 */
	public static Certificate getCertificate(final KeyStore keyStore, String alias)
		throws KeyStoreException
	{
		return keyStore.getCertificate(alias);
	}

	/**
	 * Gets the private key that is associated with the given alias from the given {@link KeyStore}
	 * object
	 *
	 * @param keyStore
	 *            the keystore
	 * @param alias
	 *            the alias
	 * @param password
	 *            the password
	 * @return the private key
	 * @throws UnrecoverableEntryException
	 *             is thrown if an entry in the keystore cannot be recovered
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws KeyStoreException
	 *             is thrown if there is an error accessing the key store
	 */
	public static PrivateKey getPrivateKey(final KeyStore keyStore, String alias, char[] password)
		throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException
	{
		KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(alias,
			new KeyStore.PasswordProtection(password));
		return entry.getPrivateKey();
	}

	/**
	 * Stores the given {@link KeyStore} object into the given keystore file
	 *
	 * @param keyStore
	 *            the keystore
	 * @param keystoreFile
	 *            the keystore file
	 * @param password
	 *            the password
	 * @throws KeyStoreException
	 *             is thrown if there is an error accessing the key store
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             is thrown if there is an error with an certificate
	 * @throws FileNotFoundException
	 *             is thrown if the keystore file not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 */
	public static void store(final KeyStore keyStore, final File keystoreFile,
		final String password)
		throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		try (FileOutputStream fos = new FileOutputStream(keystoreFile))
		{
			keyStore.store(fos, password.toCharArray());
		}
	}

	private KeyStoreExtensions()
	{
	}

}
