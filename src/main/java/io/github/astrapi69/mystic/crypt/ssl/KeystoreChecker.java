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
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class KeystoreChecker
{

	public static boolean isKeystoreFile(String filePath, String password)
	{
		try (FileInputStream fis = new FileInputStream(filePath))
		{
			KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			keystore.load(fis, password.toCharArray());
			return true; // No exception, valid keystore
		}
		catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e)
		{
			return false; // Not a valid keystore
		}
	}

	public static boolean isKeystoreFile(String filePath, String password, String[] types)
	{
		for (String type : types)
		{
			if (isKeystoreFile(filePath, type))
				return true;// Valid keystore of type 'type'
		}
		return false; // No types matched
	}

	public static boolean isKeystoreFile(File file, String password)
	{
		return isKeystoreFile(file.getAbsolutePath(), password);
	}

	public static boolean isKeystoreFile(File file, String password, String[] types)
	{
		return isKeystoreFile(file.getAbsolutePath(), password, types);
	}

}
