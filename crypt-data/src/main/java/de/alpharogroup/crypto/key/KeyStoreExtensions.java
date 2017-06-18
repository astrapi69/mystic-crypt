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
public class KeyStoreExtensions
{

	/**
	 * Delete the given alias from the given keystore file.
	 *
	 * @param keystoreFile
	 *            the keystore file
	 * @param alias
	 *            the alias
	 * @param password
	 *            the password
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 * @throws CertificateException
	 *             the certificate exception
	 * @throws FileNotFoundException
	 *             the file not found exception
	 * @throws KeyStoreException
	 *             the key store exception
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
