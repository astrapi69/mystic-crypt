package io.github.astrapi69.mystic.crypt.xml;

import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.security.PublicKey;

import org.testng.annotations.Test;

import io.github.astrapi69.crypt.data.key.reader.PublicKeyReader;
import io.github.astrapi69.file.read.ReadFileExtensions;
import io.github.astrapi69.file.search.PathFinder;

public class XmlStringEncryptorTest
{

	/**
	 * Test encrypt with {@link XmlStringEncryptor#encrypt(String)}
	 *
	 * @throws Exception
	 *             is thrown if the encryption or the decryption fails
	 */
	@Test(enabled = true)
	public void testEncrypt() throws Exception
	{

		String actual;
		String expected;
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
		String xmlString = ReadFileExtensions.fromFile(xml);

		encryptor = new XmlStringEncryptor(publicKey);
		assertNotNull(encryptor);
		encrypted = encryptor.encrypt(xmlString);
		assertNotNull(encrypted);


	}
}