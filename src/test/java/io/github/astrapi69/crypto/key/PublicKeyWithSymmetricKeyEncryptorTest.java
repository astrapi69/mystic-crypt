package io.github.astrapi69.crypto.key;

import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.testng.annotations.Test;

import de.alpharogroup.file.search.PathFinder;
import io.github.astrapi69.crypto.algorithm.AesAlgorithm;
import io.github.astrapi69.crypto.factories.SecretKeyFactoryExtensions;
import io.github.astrapi69.crypto.key.reader.PublicKeyReader;
import io.github.astrapi69.crypto.model.CryptModel;
import io.github.astrapi69.random.object.RandomStringFactory;

public class PublicKeyWithSymmetricKeyEncryptorTest
{

	@Test public void testEncrypt() throws Exception
	{
		PublicKeyWithSymmetricKeyEncryptor encryptor;

		PublicKey publicKey;
		SecretKey symmetricKey;
		CryptModel<Cipher, PublicKey, byte[]> encryptModel;
		CryptModel<Cipher, SecretKey, String> symmetricKeyModel;
		File publickeyDerDir;
		File publickeyDerFile;
		byte[] actual;
		byte[] expected;
		File encryptedCnstr;
		String encryptedFilename;
		String longString;
		// new scenario...

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		publickeyDerFile = new File(publickeyDerDir, "public.der");
		publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);

		encryptModel = CryptModel.<Cipher, PublicKey, byte[]> builder().key(publicKey).build();
		symmetricKey = SecretKeyFactoryExtensions
			.newSecretKey(AesAlgorithm.AES.getAlgorithm(), 128);
		symmetricKeyModel = CryptModel.<Cipher, SecretKey, String>builder().key(symmetricKey)
			.algorithm(AesAlgorithm.AES)
			.operationMode(Cipher.ENCRYPT_MODE)
			.build();

		encryptor = new PublicKeyWithSymmetricKeyEncryptor(encryptModel, symmetricKeyModel);
		assertNotNull(encryptor);
		longString = RandomStringFactory.newRandomLongString(10000000);

		byte[] encrypted = encryptor.encrypt(longString.getBytes(StandardCharsets.UTF_8));
		assertNotNull(encrypted);
	}
}
