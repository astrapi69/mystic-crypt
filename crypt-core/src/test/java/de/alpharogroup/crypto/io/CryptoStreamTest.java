/**
 * Copyright (C) 2015 Asterios Raptis
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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
		final String algorythm = CryptConst.PBEWITH_MD5AND_DES;

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
			encryptor.getCipher());
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
		final CryptoCipherOutputStream cos = new CryptoCipherOutputStream(decryptedOut, decryptor.getCipher());
		final FileInputStream encryptedFis = new FileInputStream(encryptedFile);

		while ((c = encryptedFis.read()) != -1)
		{
			cos.write(c);
		}

		encryptedFis.close();
		cos.close();

	}

}
