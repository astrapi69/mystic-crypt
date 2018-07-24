/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto.factories;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import lombok.experimental.UtilityClass;

/**
 * The factory class {@link KeyStoreFactory} holds methods for creating {@link KeyStore} objects.
 */
@UtilityClass
public class KeyStoreFactory
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
		return newKeyStore(type, password, keystoreFile, false);
	}

	/**
	 * Factory method for create a new empty {@link KeyStore} object and save it to the given file
	 * with the given parameters or load an existing {@link KeyStore} object from the given file.
	 *
	 * @param type
	 *            the type of the keystore
	 * @param password
	 *            the password of the keystore
	 * @param keystoreFile
	 *            the keystore file
	 * @param newEmpty
	 *            if the {@linkplain KeyStore} should be new created.
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
		final File keystoreFile, final boolean newEmpty) throws NoSuchAlgorithmException,
		CertificateException, FileNotFoundException, IOException, KeyStoreException
	{
		final KeyStore keyStore = KeyStore.getInstance(type);
		if (newEmpty)
		{
			keyStore.load(null, password.toCharArray());
			if (!keystoreFile.exists())
			{
				keystoreFile.createNewFile();
			}
			OutputStream out = new FileOutputStream(keystoreFile);
			keyStore.store(out, password.toCharArray());
			return keyStore;
		}
		keyStore.load(new FileInputStream(keystoreFile), password.toCharArray());
		return keyStore;
	}

}
