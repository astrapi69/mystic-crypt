package io.github.astrapi69.crypto.key;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

import de.alpharogroup.file.delete.DeleteFileExtensions;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.file.read.ReadFileExtensions;
import de.alpharogroup.file.search.PathFinder;
import io.github.astrapi69.crypto.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypto.model.CryptModel;

/**
 * The unit test class for the class {@link PrivateKeyFileDecryptor}
 */
public class PrivateKeyFileDecryptorTest
{
	File cryptDir;
	File decrypted;
	File encrypted;
	File toEncrypt;

	/**
	 * Sets up method will be invoked before every unit test method in this class
	 */
	@BeforeMethod
	protected void setUp()
	{
		cryptDir = new File(PathFinder.getSrcTestResourcesDir(), "crypt");
		toEncrypt = new File(cryptDir, "test.txt");
	}

	/**
	 * Test method for {@link PrivateKeyFileDecryptor#decrypt(File)}
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public void testDecrypt() throws Exception
	{
		String actual;
		String expected;
		PublicKey publicKey;
		PrivateKey privateKey;
		CryptModel<Cipher, PrivateKey, String> decryptModel;
		CryptModel<Cipher, PublicKey, String> encryptModel;
		File derDir;
		File privatekeyDerFile;
		PublicKeyFileEncryptor encryptor;
		PrivateKeyFileDecryptor decryptor;

		actual = ReadFileExtensions.readFromFile(toEncrypt);

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privatekeyDerFile = new File(derDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		decryptModel = CryptModel.<Cipher, PrivateKey, String> builder().key(privateKey).build();
		publicKey = PrivateKeyExtensions.generatePublicKey(privateKey);
		encryptModel = CryptModel.<Cipher, PublicKey, String> builder().key(publicKey).build();
		encryptor = new PublicKeyFileEncryptor(encryptModel);
		assertNotNull(encryptor);

		decryptor = new PrivateKeyFileDecryptor(decryptModel);
		assertNotNull(decryptor);

		encrypted = encryptor.encrypt(toEncrypt);
		assertNotNull(encrypted);

		decrypted = decryptor.decrypt(encrypted);
		assertNotNull(decrypted);
		expected = ReadFileExtensions.readFromFile(decrypted);
		assertEquals(expected, actual);
		// clean up...
		DeleteFileExtensions.delete(encrypted);
		DeleteFileExtensions.delete(decrypted);
	}

}
