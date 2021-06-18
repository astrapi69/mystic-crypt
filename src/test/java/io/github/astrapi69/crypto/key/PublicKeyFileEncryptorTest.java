package io.github.astrapi69.crypto.key;

import de.alpharogroup.file.delete.DeleteFileExtensions;
import de.alpharogroup.file.search.PathFinder;
import io.github.astrapi69.crypto.algorithm.SunJCEAlgorithm;
import io.github.astrapi69.crypto.file.PBEFileDecryptor;
import io.github.astrapi69.crypto.file.PBEFileEncryptor;
import io.github.astrapi69.crypto.key.reader.PublicKeyReader;
import io.github.astrapi69.crypto.model.CryptModel;
import io.github.astrapi69.crypto.model.StringDecorator;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import javax.crypto.Cipher;
import java.io.File;
import java.security.PublicKey;

import static org.testng.Assert.*;
import static org.testng.AssertJUnit.assertNotNull;

/**
 * The unit test class for the class {@link PublicKeyFileEncryptor}
 */
public class PublicKeyFileEncryptorTest
{

	File cryptDir;
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
	 * Test method for {@link PublicKeyFileEncryptor#encrypt(File)}
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test public void testEncrypt() throws Exception
	{
		PublicKey publicKey;
		PublicKeyFileEncryptor encryptor;
		CryptModel<Cipher, PublicKey, String> encryptModel;
		File publickeyDerDir;
		File publickeyDerFile;

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		publickeyDerFile = new File(publickeyDerDir, "public.der");
		publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);

		encryptModel = CryptModel.<Cipher, PublicKey, String> builder().key(publicKey).build();

		encryptor = new PublicKeyFileEncryptor(encryptModel);
		assertNotNull(encryptor);

		encrypted = encryptor.encrypt(toEncrypt);
		assertNotNull(encrypted);
		// clean up...
		DeleteFileExtensions.delete(encrypted);
	}
}
