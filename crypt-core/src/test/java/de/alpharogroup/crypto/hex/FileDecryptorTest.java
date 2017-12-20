package de.alpharogroup.crypto.hex;


import java.io.File;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import de.alpharogroup.crypto.CryptConst;
import de.alpharogroup.crypto.algorithm.KeyPairWithModeAndPaddingAlgorithm;
import de.alpharogroup.crypto.algorithm.MacAlgorithm;
import de.alpharogroup.crypto.algorithm.SunJCEAlgorithm;
import de.alpharogroup.crypto.model.CryptModel;
import de.alpharogroup.file.delete.DeleteFileExtensions;
import org.testng.annotations.Test;

import de.alpharogroup.file.search.PathFinder;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;

public class FileDecryptorTest
{

	@Test
	public void testDecrypt() throws Exception {
		// TODO
		final File cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		final File toEncrypt = new File(cryptDir, "test.txt");

		final String firstKey = "D1D15ED36B887AF1";

		final CryptModel<Cipher, String> cryptModel = CryptModel.<Cipher, String>builder()
				.key(firstKey)
				.algorithm(SunJCEAlgorithm.PBEWithMD5AndDES)
				.build();

		final FileEncryptor encryptor = new FileEncryptor(cryptModel) {

			/** The Constant serialVersionUID. */
			private static final long serialVersionUID = 1L;

			@Override
			protected File newEncryptedFile(final String parent, final String child) {
				return new File(cryptDir, "encrypted2.txt");
			}
		};
		final File encrypted = encryptor.encrypt(toEncrypt);

		final FileDecryptor decryptor = new FileDecryptor(cryptModel) {

			/** The Constant serialVersionUID. */
			private static final long serialVersionUID = 1L;

			@Override
			protected File newDecryptedFile(final String parent, final String child) {
				return new File(cryptDir, "decrypted2.txt");
			}
		};

		final File decrypted = decryptor.decrypt(encrypted);

		DeleteFileExtensions.delete(encrypted);
		DeleteFileExtensions.delete(decrypted);
	}

}
