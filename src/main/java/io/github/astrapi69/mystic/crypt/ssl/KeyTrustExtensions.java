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
package io.github.astrapi69.mystic.crypt.ssl;

import java.io.File;
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

import io.github.astrapi69.crypt.data.factory.KeyStoreFactory;

/**
 * The factory class {@link KeyTrustExtensions} holds methods for creating {@link TrustManager}
 * array objects and {@link KeyManager} array objects.
 */
public final class KeyTrustExtensions
{

	private KeyTrustExtensions()
	{
	}

	/**
	 * Resolve the {@link KeyManager} array from the keystore that is resolved from the given
	 * parameters.
	 *
	 * @param keystoreType
	 *            the keystore type
	 * @param password
	 *            the password
	 * @param keystoreFile
	 *            the keystore file
	 * @param keyManagerAlgorithm
	 *            the key manager algorithm
	 * @return the key manager[]
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             is thrown if there is an error with an certificate
	 * @throws FileNotFoundException
	 *             is thrown if the keystore file not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws KeyStoreException
	 *             is thrown if there is an error accessing the key store
	 * @throws UnrecoverableKeyException
	 *             is thrown if an key entry in the keystore cannot be recovered
	 */
	public static KeyManager[] resolveKeyManagers(final String keystoreType, final String password,
		final File keystoreFile, final String keyManagerAlgorithm)
		throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException,
		KeyStoreException, UnrecoverableKeyException
	{
		final KeyStore keyStore = KeyStoreFactory.loadKeyStore(keystoreFile, keystoreType,
			password);
		final KeyManagerFactory keyFactory = KeyManagerFactory.getInstance(keyManagerAlgorithm);
		keyFactory.init(keyStore, password.toCharArray());
		final KeyManager[] keyManagers = keyFactory.getKeyManagers();
		return keyManagers;
	}

	/**
	 * Resolve the {@link TrustManager} array from the keystore that is resolved from the given
	 * parameters.
	 *
	 * @param keystoreType
	 *            the keystore type
	 * @param password
	 *            the password
	 * @param keystoreFile
	 *            the keystore file
	 * @param trustManagerAlgorithm
	 *            the trust manager algorithm
	 * @return the trust manager[]
	 *
	 * @throws NoSuchAlgorithmException
	 *             is thrown if instantiation of the SecretKeyFactory object fails
	 * @throws CertificateException
	 *             is thrown if there is an error with an certificate
	 * @throws FileNotFoundException
	 *             is thrown if the keystore file not found
	 * @throws IOException
	 *             Signals that an I/O exception has occurred.
	 * @throws KeyStoreException
	 *             is thrown if there is an error accessing the key store
	 */
	public static TrustManager[] resolveTrustManagers(final String keystoreType,
		final String password, final File keystoreFile, final String trustManagerAlgorithm)
		throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException,
		KeyStoreException
	{
		final KeyStore keyStore = KeyStoreFactory.loadKeyStore(keystoreFile, keystoreType,
			password);
		final TrustManagerFactory trustFactory = TrustManagerFactory
			.getInstance(trustManagerAlgorithm);
		trustFactory.init(keyStore);
		final TrustManager[] trustManagers = trustFactory.getTrustManagers();
		return trustManagers;
	}

}
