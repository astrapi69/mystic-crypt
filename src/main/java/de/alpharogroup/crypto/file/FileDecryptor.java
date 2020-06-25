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
package de.alpharogroup.crypto.file;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.io.FilenameUtils;

import de.alpharogroup.crypto.core.AbstractFileDecryptor;
import de.alpharogroup.crypto.decorator.CryptObjectDecoratorExtensions;
import de.alpharogroup.crypto.io.CryptoCipherOutputStream;
import de.alpharogroup.crypto.model.CryptModel;
import de.alpharogroup.crypto.model.CryptObjectDecorator;
import de.alpharogroup.file.read.ReadFileExtensions;
import de.alpharogroup.file.write.WriteFileExtensions;

/**
 * The class {@link FileDecryptor} can decrypt files from the given crypt model
 * bean.
 */
public class FileDecryptor extends AbstractFileDecryptor {

	/** The Constant serialVersionUID. */
	private static final long serialVersionUID = 1L;

	/** The decrypted file. */
	private File decryptedFile;

	/**
	 * Instantiates a new {@link FileDecryptor} object
	 *
	 * @param model the model
	 * @throws InvalidKeyException                the invalid key exception
	 * @throws NoSuchAlgorithmException           is thrown if instantiation of the
	 *                                            SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException            is thrown if generation of the
	 *                                            SecretKey object fails.
	 * @throws NoSuchPaddingException             the no such padding exception
	 * @throws InvalidAlgorithmParameterException is thrown if initialization of the
	 *                                            cipher object fails.
	 * @throws UnsupportedEncodingException       is thrown if the named charset is
	 *                                            not supported.
	 */
	public FileDecryptor(final CryptModel<Cipher, String, String> model)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, UnsupportedEncodingException {
		super(model);
	}

	/**
	 * Instantiates a new file decryptor.
	 *
	 * @param model         the model
	 * @param decryptedFile is the target of the result from the decryption, if null
	 *                      the default file will be created. If null the name
	 *                      convention is given name of the encrypted file with the
	 *                      extension '.decrypted'.
	 * @throws InvalidKeyException                the invalid key exception
	 * @throws NoSuchAlgorithmException           is thrown if instantiation of the
	 *                                            SecretKeyFactory object fails.
	 * @throws InvalidKeySpecException            is thrown if generation of the
	 *                                            SecretKey object fails.
	 * @throws NoSuchPaddingException             the no such padding exception
	 * @throws InvalidAlgorithmParameterException is thrown if initialization of the
	 *                                            cipher object fails.
	 * @throws UnsupportedEncodingException       is thrown if the named charset is
	 *                                            not supported.
	 */
	public FileDecryptor(final CryptModel<Cipher, String, String> model, final File decryptedFile)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, UnsupportedEncodingException {
		super(model);
		this.decryptedFile = decryptedFile;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public File decrypt(final File encrypted) throws Exception {
		Objects.requireNonNull(encrypted);
		onBeforeDecrypt(encrypted);
		onDecrypt(encrypted);
		onAfterDecrypt(encrypted);
		return decryptedFile;
	}

	/**
	 *
	 * Factory method for creating the new decrypted {@link File} if it is not
	 * exists. This method is invoked in the constructor from the derived classes
	 * and can be overridden so users can provide their own version of creating the
	 * new decrypted {@link File}
	 *
	 * @param parent the parent directory
	 * @param child  the file name
	 * @return the new {@link File} object
	 */
	protected File newDecryptedFile(final String parent, final String child) {
		return new File(parent, child);
	}

	protected void onAfterDecrypt(final File encrypted) throws IOException {
		Objects.requireNonNull(encrypted);
		String decryptedFileString = ReadFileExtensions.readFromFile(decryptedFile);
		List<CryptObjectDecorator<String>> decorators = getModel().getDecorators();
		if (decorators != null && !decorators.isEmpty()) {
			for (int i = decorators.size() - 1; 0 <= i; i--) {
				decryptedFileString = CryptObjectDecoratorExtensions.undecorateFile(decryptedFile, decorators.get(i));
			}
		}
		WriteFileExtensions.writeStringToFile(decryptedFile, decryptedFileString, Charset.forName("UTF-8").name());
	}

	protected void onBeforeDecrypt(final File encrypted) {
		Objects.requireNonNull(encrypted);
		if (decryptedFile == null) {
			final String filename = FilenameUtils.getBaseName(encrypted.getName());
			decryptedFile = newDecryptedFile(encrypted.getParent(), filename + ".decrypted");
		}
	}

	protected void onDecrypt(final File encrypted) throws Exception {
		Objects.requireNonNull(encrypted);
		try (FileOutputStream decryptedOut = new FileOutputStream(decryptedFile);
				CryptoCipherOutputStream cos = new CryptoCipherOutputStream(decryptedOut, getModel().getCipher());
				InputStream fileInputStream = new FileInputStream(encrypted)) {
			int c;
			while ((c = fileInputStream.read()) != -1) {
				cos.write(c);
			}
		}
	}

}
