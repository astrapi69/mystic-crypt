package io.github.astrapi69.mystic.crypt.xml;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.testng.annotations.Test;

import io.github.astrapi69.crypt.data.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.file.read.ReadFileExtensions;
import io.github.astrapi69.file.search.PathFinder;
import io.github.astrapi69.mystic.crypt.key.PrivateKeyHexDecryptor;

public class XmlStringEnDecryptorTest
{

	/**
	 * Test encrypt and decrypt with {@link XmlStringEncryptor#encrypt(String)} and
	 * {@link PrivateKeyHexDecryptor#decrypt(String)} loaded from pem files
	 *
	 * @throws Exception
	 *             is thrown if the encryption or the decryption fails
	 */
	@Test(enabled = true)
	public void testEncryptDecrypt() throws Exception
	{

		String actual;
		String expected;
		String xmlString;
		XmlStringEncryptor encryptor;
		PublicKey publicKey;
		File publickeyDerDir;
		File publickeyDerFile;
		File xml;
		byte[] encrypted;

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		publickeyDerFile = new File(publickeyDerDir, "public.der");
		publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);
		xml = PathFinder.getRelativePath(PathFinder.getSrcTestResourcesDir(), "xml", "company.xml");
		xmlString = ReadFileExtensions.fromFile(xml);
		expected = xmlString;

		encryptor = new XmlStringEncryptor(publicKey);
		assertNotNull(encryptor);
		encrypted = encryptor.encrypt(xmlString);
		assertNotNull(encrypted);

		PrivateKey privateKey;
		File derDir;
		File privatekeyDerFile;
		XmlStringDecryptor decryptor;

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privatekeyDerFile = new File(derDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		decryptor = new XmlStringDecryptor(privateKey);

		String decrypted = decryptor.decrypt(encrypted);
		actual = decrypted;
		assertEquals(expected, actual);
	}
}