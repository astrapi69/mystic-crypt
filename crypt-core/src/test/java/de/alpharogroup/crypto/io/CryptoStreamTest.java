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
package de.alpharogroup.crypto.io;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;

import org.testng.annotations.Test;

import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.simple.SimpleBaseDecryptor;
import de.alpharogroup.crypto.simple.SimpleBaseEncryptor;
import de.alpharogroup.file.search.PathFinder;

public class CryptoStreamTest
{

	@Test
	public void testReadAndWriteToDecryptedFileWithCipherIO()
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, IOException
	{
		final String algorythm = CryptConst.PBE_WITH_MD5_AND_DES;

		final String firstKey = "D1D15ED36B887AF1";
		final File cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		final File toEncrypt = new File(cryptDir, "test.txt");
		System.out.println(toEncrypt.getAbsolutePath());

		final InputStream fis = new FileInputStream(toEncrypt);
		final SimpleBaseEncryptor encryptor = new SimpleBaseEncryptor(firstKey) {

			/** The Constant serialVersionUID. */
			private static final long serialVersionUID = 1L;

			@Override
			protected SecretKeyFactory newSecretKeyFactory(final String algorithm)
				throws NoSuchAlgorithmException
			{
				return super.newSecretKeyFactory(algorythm);
			}
		};
		final CryptoCipherInputStream cis = new CryptoCipherInputStream(fis,
			encryptor.getModel().getCipher());
		final File encryptedFile = new File(cryptDir, "encrypted.txt");
		System.out.println(encryptedFile.getAbsolutePath());
		final FileOutputStream out = new FileOutputStream(encryptedFile);

		int c;

		while ((c = cis.read()) != -1)
		{
			out.write(c);
		}

		cis.close();
		out.close();

		final File outputDecrypted = new File(cryptDir, "decrypted.txt");

		final FileOutputStream decryptedOut = new FileOutputStream(outputDecrypted);
		final SimpleBaseDecryptor decryptor = new SimpleBaseDecryptor(firstKey){

			/** The Constant serialVersionUID. */
			private static final long serialVersionUID = 1L;

			@Override
			protected SecretKeyFactory newSecretKeyFactory(final String algorithm)
				throws NoSuchAlgorithmException
			{
				return super.newSecretKeyFactory(algorythm);
			}
		};
		final CryptoCipherOutputStream cos = new CryptoCipherOutputStream(decryptedOut, decryptor.getModel().getCipher());
		final FileInputStream encryptedFis = new FileInputStream(encryptedFile);

		while ((c = encryptedFis.read()) != -1)
		{
			cos.write(c);
		}

		encryptedFis.close();
		cos.close();

	}

}
