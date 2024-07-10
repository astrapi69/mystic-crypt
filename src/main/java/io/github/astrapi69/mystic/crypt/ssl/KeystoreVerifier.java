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

/**
 * This class provides methods to check and verify if a file is a valid Java keystore.
 */
public class KeystoreVerifier
{

	/**
	 * Checks if the specified file path corresponds to a valid keystore.
	 *
	 * @param filePath
	 *            the path of the file to be checked
	 * @param password
	 *            the password to access the keystore
	 * @return true if the file is a valid keystore, false otherwise
	 */
	public static boolean isKeystoreFile(String filePath, String password)
	{
		return isKeystoreFile(filePath, password.toCharArray());
	}

	/**
	 * Checks if the specified file path corresponds to a valid keystore.
	 *
	 * @param filePath
	 *            the path of the file to be checked
	 * @param password
	 *            the password to access the keystore
	 * @return true if the file is a valid keystore, false otherwise
	 */
	public static boolean isKeystoreFile(String filePath, char[] password)
	{
		return isKeystoreFile(filePath, password, KeyStore.getDefaultType());
	}

	/**
	 * Checks if the specified file path corresponds to a valid keystore.
	 *
	 * @param filePath
	 *            the path of the file to be checked
	 * @param password
	 *            the password to access the keystore
	 * @param type
	 *            The type to check against
	 * @return true if the file is a valid keystore, false otherwise
	 */
	public static boolean isKeystoreFile(String filePath, String password, String type)
	{
		return isKeystoreFile(filePath, password.toCharArray(), type);
	}

	/**
	 * Checks if the specified file path corresponds to a valid keystore.
	 *
	 * @param filePath
	 *            the path of the file to be checked
	 * @param password
	 *            the password to access the keystore as char array
	 * @param type
	 *            The type to check against
	 * @return true if the file is a valid keystore, false otherwise
	 */
	public static boolean isKeystoreFile(String filePath, char[] password, String type)
	{
		try (FileInputStream fis = new FileInputStream(filePath))
		{
			KeyStore keystore = KeyStore.getInstance(type);
			keystore.load(fis, password);
			return true;
		}
		catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e)
		{
			return false;
		}
	}

	/**
	 * Overloaded method to check if the specified file path corresponds to a valid keystore for any
	 * of the specified types.
	 *
	 * @param filePath
	 *            the path of the file to be checked
	 * @param password
	 *            the password to access the keystore
	 * @param types
	 *            an array of keystore types to check against
	 * @return true if the file is a valid keystore for any of the specified types, false otherwise
	 */
	public static boolean isKeystoreFile(String filePath, String password, String[] types)
	{
		return isKeystoreFile(filePath, password.toCharArray(), types);
	}

	/**
	 * Overloaded method to check if the specified file path corresponds to a valid keystore for any
	 * of the specified types.
	 *
	 * @param filePath
	 *            the path of the file to be checked
	 * @param password
	 *            the password to access the keystore
	 * @param types
	 *            an array of keystore types to check against
	 * @return true if the file is a valid keystore for any of the specified types, false otherwise
	 */
	public static boolean isKeystoreFile(String filePath, char[] password, String[] types)
	{
		for (String type : types)
		{
			if (isKeystoreFile(filePath, password, type))
				return true;
		}
		return false;
	}

	/**
	 * Checks if the specified file object corresponds to a valid keystore.
	 *
	 * @param file
	 *            the file to be checked
	 * @param password
	 *            the password to access the keystore
	 * @return true if the file is a valid keystore, false otherwise
	 */
	public static boolean isKeystoreFile(File file, char[] password)
	{
		return isKeystoreFile(file.getAbsolutePath(), password);
	}

	/**
	 * Checks if the specified file object corresponds to a valid keystore.
	 *
	 * @param file
	 *            the file to be checked
	 * @param password
	 *            the password to access the keystore
	 * @param type
	 *            The type to check against
	 * @return true if the file is a valid keystore, false otherwise
	 */
	public static boolean isKeystoreFile(File file, char[] password, String type)
	{
		return isKeystoreFile(file.getAbsolutePath(), password, type);
	}

	/**
	 * Checks if the specified file object corresponds to a valid keystore.
	 *
	 * @param file
	 *            the file to be checked
	 * @param password
	 *            the password to access the keystore
	 * @param type
	 *            The type to check against
	 * @return true if the file is a valid keystore, false otherwise
	 */
	public static boolean isKeystoreFile(File file, String password, String type)
	{
		return isKeystoreFile(file.getAbsolutePath(), password.toCharArray(), type);
	}

	/**
	 * Checks if the specified file object corresponds to a valid keystore.
	 *
	 * @param file
	 *            the file to be checked
	 * @param password
	 *            the password to access the keystore
	 * @return true if the file is a valid keystore, false otherwise
	 */
	public static boolean isKeystoreFile(File file, String password)
	{
		return isKeystoreFile(file.getAbsolutePath(), password);
	}

	/**
	 * Overloaded method to check if the specified file object corresponds to a valid keystore for
	 * any of the specified types.
	 *
	 * @param file
	 *            the file to be checked
	 * @param password
	 *            the password to access the keystore
	 * @param types
	 *            an array of keystore types to check against
	 * @return true if the file is a valid keystore for any of the specified types, false otherwise
	 */
	public static boolean isKeystoreFile(File file, String password, String[] types)
	{
		return isKeystoreFile(file.getAbsolutePath(), password, types);
	}

	/**
	 * Overloaded method to check if the specified file object corresponds to a valid keystore for
	 * any of the specified types.
	 *
	 * @param file
	 *            the file to be checked
	 * @param password
	 *            the password to access the keystore
	 * @param types
	 *            an array of keystore types to check against
	 * @return true if the file is a valid keystore for any of the specified types, false otherwise
	 */
	public static boolean isKeystoreFile(File file, char[] password, String[] types)
	{
		return isKeystoreFile(file.getAbsolutePath(), password, types);
	}

}
