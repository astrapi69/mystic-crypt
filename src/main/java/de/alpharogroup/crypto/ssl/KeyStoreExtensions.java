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
package de.alpharogroup.crypto.ssl;

import de.alpharogroup.crypto.algorithm.KeystoreType;
import de.alpharogroup.crypto.factories.KeyStoreFactory;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

/**
 * The extension class {@link KeyStoreExtensions} provides extension methods for the {@link KeyStore}
 */
public final class KeyStoreExtensions
{
	private KeyStoreExtensions()
	{
	}

	/**
	 * Add the given private key to the given {@link KeyStore} object
	 *
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
	 * Add the given certificate to the given {@link KeyStore} object.
	 *
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
	public static void addCertificate(final KeyStore keyStore, String alias, Certificate certificate)
		throws KeyStoreException
	{
		keyStore.setCertificateEntry(alias, certificate);
	}

	/**
	 * Gets the private key that is associated with the given alias from the given {@link KeyStore} object
	 *
	 * @param keyStore
	 *            the keystore
	 * @param alias
	 *            the alias
	 * @param password
	 *            the password
	 * @return
	 *            the private key
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
		KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry)keyStore
			.getEntry(alias, new KeyStore.PasswordProtection(password));
		return entry.getPrivateKey();
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
		KeyStore keyStore = KeyStoreFactory.newKeyStore(KeystoreType.JKS.name(), password,
			keystoreFile);

		keyStore.deleteEntry(alias);
		keyStore.store(new FileOutputStream(keystoreFile), password.toCharArray());
	}

}
