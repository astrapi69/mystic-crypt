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
package io.github.astrapi69.mystic.crypt.pw;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.text.Normalizer;
import java.util.Objects;

import javax.crypto.Cipher;

import org.apache.commons.io.FilenameUtils;

import io.github.astrapi69.crypt.api.ByteArrayDecryptor;
import io.github.astrapi69.crypt.api.Cryptor;
import io.github.astrapi69.crypt.api.FileDecryptor;
import io.github.astrapi69.mystic.crypt.io.CryptoCipherOutputStream;

/**
 * The class {@link PasswordFileDecryptor} is a simple {@link ByteArrayDecryptor} implementation
 *
 * @author Asterios Raptis
 * @version 1.0
 */
public class PasswordFileDecryptor implements FileDecryptor, Cryptor
{

	/** The decrypted file. */
	private File decryptedFile;

	/**
	 * The normalized password.
	 */
	private String normalizedPassword;

	/**
	 * Instantiates a new {@link PasswordFileDecryptor} with the given password
	 *
	 * @param password
	 *            The password
	 * @param decryptedFile
	 *            is the target of the result from the decryption, if null the default file will be
	 *            created. If null the name convention is given name of the encrypted file with the
	 *            extension '.decrypted'.
	 */
	public PasswordFileDecryptor(final String password, final File decryptedFile)
	{
		Objects.requireNonNull(password);
		this.decryptedFile = decryptedFile;
		this.normalizedPassword = Normalizer.normalize(password, Normalizer.Form.NFC);
	}

	/**
	 * {@inheritDoc}
	 *
	 * <p>
	 * The salt is read from the first bytes of the encrypted file, matching what
	 * {@link PasswordFileEncryptor#encrypt(File)} writes.
	 */
	@Override
	public File decrypt(final File encrypted) throws Exception
	{
		Objects.requireNonNull(encrypted);

		if (decryptedFile == null)
		{
			final String filename = FilenameUtils.getBaseName(encrypted.getName());
			decryptedFile = newDecryptedFile(encrypted.getParent(), filename + ".decrypted");
		}
		try (FileInputStream fis = new FileInputStream(encrypted))
		{
			byte[] salt = fis.readNBytes(PbeCipherSupport.SALT_LENGTH);
			if (salt.length < PbeCipherSupport.SALT_LENGTH)
			{
				throw new IllegalArgumentException(
					"encrypted file too short to contain a salt prefix");
			}
			Cipher cipher = PbeCipherSupport.newCipher(normalizedPassword, newOperationMode(),
				salt);
			try (FileOutputStream decryptedOut = new FileOutputStream(decryptedFile);
				CryptoCipherOutputStream cos = new CryptoCipherOutputStream(decryptedOut, cipher))
			{
				int c;
				while ((c = fis.read()) != -1)
				{
					cos.write(c);
				}
			}
		}
		return decryptedFile;
	}

	/**
	 * Resets the password, wiping it from memory. Since the password is now needed on every
	 * {@link #decrypt(File)} call rather than only once at construction, calling this makes any
	 * subsequent {@code decrypt} call fail.
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
		return Cipher.DECRYPT_MODE;
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
	protected File newDecryptedFile(final String parent, final String child)
	{
		return new File(parent, child);
	}
}
