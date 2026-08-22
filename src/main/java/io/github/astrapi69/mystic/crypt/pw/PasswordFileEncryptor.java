/*
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
package io.github.astrapi69.mystic.crypt.pw;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.text.Normalizer;
import java.util.Objects;

import javax.crypto.Cipher;

import org.apache.commons.io.FilenameUtils;

import io.github.astrapi69.crypt.api.Cryptor;
import io.github.astrapi69.crypt.api.FileEncryptor;
import io.github.astrapi69.mystic.crypt.io.CryptoCipherInputStream;

/**
 * The class {@link PasswordFileEncryptor} is a simple {@link FileEncryptor} implementation.
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class PasswordFileEncryptor implements FileEncryptor, Cryptor
{

	/** The encrypted file. */
	private File encryptedFile;

	/**
	 * The normalized password.
	 */
	private String normalizedPassword;

	/**
	 * Instantiates a new {@link PasswordFileEncryptor} with the given password
	 *
	 * @param password
	 *            The password
	 */
	public PasswordFileEncryptor(final String password)
	{
		this(password, null);
	}

	/**
	 * Instantiates a new {@link PasswordFileEncryptor} with the given password
	 *
	 * @param password
	 *            The password
	 * @param encryptedFile
	 *            The file that is the target of the result from the encryption, if null the default
	 *            file will be created. If null the name convention is given name of the file that
	 *            has to be encrypted with the extension '.enc'.
	 */
	public PasswordFileEncryptor(final String password, final File encryptedFile)
	{
		Objects.requireNonNull(password);
		this.encryptedFile = encryptedFile;
		this.normalizedPassword = Normalizer.normalize(password, Normalizer.Form.NFC);
	}

	/**
	 * {@inheritDoc}
	 *
	 * <p>
	 * A fresh, random salt is generated and written as the first bytes of the encrypted file on
	 * every call.
	 */
	public File encrypt(final File toEncrypt) throws Exception
	{
		Objects.requireNonNull(toEncrypt);
		if (encryptedFile == null)
		{
			final String filename = FilenameUtils.getBaseName(toEncrypt.getName());
			encryptedFile = newEncryptedFile(toEncrypt.getParent(), filename + ".enc");
		}
		byte[] salt = PbeCipherSupport.newSalt();
		Cipher cipher = PbeCipherSupport.newCipher(normalizedPassword, newOperationMode(), salt);
		try (OutputStream out = new FileOutputStream(encryptedFile))
		{
			out.write(salt);
			try (CryptoCipherInputStream cis = new CryptoCipherInputStream(
				new FileInputStream(toEncrypt), cipher))
			{
				int c;
				while ((c = cis.read()) != -1)
				{
					out.write(c);
				}
			}
		}
		return encryptedFile;
	}

	/**
	 * Resets the password, wiping it from memory. Since the password is now needed on every
	 * {@link #encrypt(File)} call rather than only once at construction, calling this makes any
	 * subsequent {@code encrypt} call fail.
	 */
	public synchronized void resetPassword()
	{
		this.normalizedPassword = null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int newOperationMode()
	{
		return Cipher.ENCRYPT_MODE;
	}

	/**
	 *
	 * Factory method for creating the new decrypted {@link File} if it is not exists. This method
	 * is invoked in the constructor from the derived classes and can be overridden so users can
	 * provide their own version of creating the new decrypted {@link File}
	 *
	 * @param parent
	 *            the parent directory
	 * @param child
	 *            the file name
	 * @return the new {@link File} object
	 */
	protected File newEncryptedFile(final String parent, final String child)
	{
		return new File(parent, child);
	}
}
