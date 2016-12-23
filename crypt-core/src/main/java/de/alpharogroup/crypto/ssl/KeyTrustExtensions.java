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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import lombok.experimental.UtilityClass;

/**
 * The class {@link KeyTrustExtensions}.
 */
@UtilityClass
public class KeyTrustExtensions
{

	/**
	 * Factory method for load the {@link KeyStore} object from the given file.
	 *
	 * @param type
	 *            the type of the keystore
	 * @param password
	 *            the password of the keystore
	 * @param keystoreFile
	 *            the keystore file
	 * @return the loaded {@link KeyStore} object
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 * @throws CertificateException
	 *             the certificate exception
	 * @throws FileNotFoundException
	 *             the file not found exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws KeyStoreException
	 *             the key store exception
	 */
	public static KeyStore newKeyStore(final String type, final String password,
		final File keystoreFile) throws NoSuchAlgorithmException, CertificateException,
		FileNotFoundException, IOException, KeyStoreException
	{
		final KeyStore keyStore = KeyStore.getInstance(type);
		keyStore.load(new FileInputStream(keystoreFile), password.toCharArray());
		return keyStore;
	}

	/**
	 * Resolve the {@link TrustManager} array from the keystore that is resolved from the given
	 * parameters.
	 *
	 * @param type
	 *            the type
	 * @param password
	 *            the password
	 * @param keystoreFile
	 *            the keystore file
	 * @param trustManagerAlgorithm
	 *            the trust manager algorithm
	 * @return the trust manager[]
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 * @throws CertificateException
	 *             the certificate exception
	 * @throws FileNotFoundException
	 *             the file not found exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws KeyStoreException
	 *             the key store exception
	 */
	public static TrustManager[] resolveTrustManagers(final String type, final String password,
		final File keystoreFile, final String trustManagerAlgorithm)
		throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException,
		KeyStoreException
	{
		final KeyStore keyStore = newKeyStore(type, password, keystoreFile);
		final TrustManagerFactory trustFactory = TrustManagerFactory
			.getInstance(trustManagerAlgorithm);
		trustFactory.init(keyStore);
		final TrustManager[] trustManagers = trustFactory.getTrustManagers();
		return trustManagers;
	}

	/**
	 * Resolve the {@link KeyManager} array from the keystore that is resolved from the given
	 * parameters.
	 *
	 * @param type
	 *            the type
	 * @param password
	 *            the password
	 * @param keystoreFile
	 *            the keystore file
	 * @param keyManagerAlgorithm
	 *            the key manager algorithm
	 * @return the key manager[]
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 * @throws CertificateException
	 *             the certificate exception
	 * @throws FileNotFoundException
	 *             the file not found exception
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws KeyStoreException
	 *             the key store exception
	 * @throws UnrecoverableKeyException
	 *             the unrecoverable key exception
	 */
	public static KeyManager[] resolveKeyManagers(final String type, final String password,
		final File keystoreFile, final String keyManagerAlgorithm)
		throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException,
		KeyStoreException, UnrecoverableKeyException
	{
		final KeyStore keyStore = newKeyStore(type, password, keystoreFile);
		final KeyManagerFactory keyFactory = KeyManagerFactory.getInstance(keyManagerAlgorithm);
		keyFactory.init(keyStore, password.toCharArray());
		final KeyManager[] keyManagers = keyFactory.getKeyManagers();
		return keyManagers;
	}

}
