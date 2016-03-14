package de.alpharogroup.crypto.io;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;

import org.apache.commons.io.IOUtils;
import org.testng.annotations.Test;

import de.alpharogroup.BaseStreamEncryptor;
import de.alpharogroup.SimpleBaseDecryptor;
import de.alpharogroup.SimpleBaseEncryptor;
import de.alpharogroup.crypto.BaseEncryptor;
import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.interfaces.GenericDecryptor;
import de.alpharogroup.file.search.PathFinder;
import de.alpharogroup.file.write.WriteFileExtensions;

public class CryptoStreamTest
{

//	@Test
	public void testReadAndWriteToEncryptedFile()
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, IOException
	{

		final String firstKey = "D1D15ED36B887AF1";
		final File cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		final File toEncrypt = new File(cryptDir, "test.txt");
		System.out.println(toEncrypt.getAbsolutePath());

		final InputStream fis = new FileInputStream(toEncrypt);
		final BaseStreamEncryptor encryptor = new BaseStreamEncryptor(firstKey);
		final CryptoInputStream cis = new CryptoInputStream(new FileInputStream(toEncrypt),
			encryptor);
		final File output = new File(cryptDir, "encrypted.txt");
		System.out.println(output.getAbsolutePath());
		final FileOutputStream out = new FileOutputStream(output);

		int c;

		while ((c = cis.read()) != -1)
		{
			out.write(c);
		}

		cis.close();
		out.close();

	}

	@Test
	public void testReadAndWriteToDecryptedFile()
		throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
		NoSuchPaddingException, InvalidAlgorithmParameterException, IOException
	{
		final String algorythm = CryptConst.PBEWITH_SHA1_AND_DES_EDE;

		final String firstKey = "D1D15ED36B887AF1";
		final File cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		final File toEncrypt = new File(cryptDir, "test.txt");
		System.out.println(toEncrypt.getAbsolutePath());

		final InputStream fis = new FileInputStream(toEncrypt);
		final BaseStreamEncryptor encryptor = new BaseStreamEncryptor(firstKey) {
			@Override
			protected SecretKeyFactory newSecretKeyFactory(final String algorithm)
				throws NoSuchAlgorithmException
			{
				return super.newSecretKeyFactory(algorythm);
			}
		};
		final CryptoInputStream cis = new CryptoInputStream(new FileInputStream(toEncrypt),
			encryptor);
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

		final GenericDecryptor<Integer, Integer> decryptor = new SimpleBaseDecryptor(firstKey){
			@Override
			protected SecretKeyFactory newSecretKeyFactory(final String algorithm)
				throws NoSuchAlgorithmException
			{
				return super.newSecretKeyFactory(algorythm);
			}
		};
		final CryptoOutputStream cos = new CryptoOutputStream(out, decryptor);
		final File outputDecrypted = new File(cryptDir, "decrypted.txt");
		final FileInputStream encryptedFis = new FileInputStream(encryptedFile);

		while ((c = encryptedFis.read()) != -1)
		{
			cos.write(c);
		}

		encryptedFis.close();
		cos.close();

	}

}
