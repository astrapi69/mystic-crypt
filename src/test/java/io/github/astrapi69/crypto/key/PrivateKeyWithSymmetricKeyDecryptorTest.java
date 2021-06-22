package io.github.astrapi69.crypto.key;

import static org.testng.AssertJUnit.assertEquals;
import static org.testng.AssertJUnit.assertNotNull;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.testng.annotations.Test;

import de.alpharogroup.file.search.PathFinder;
import io.github.astrapi69.crypto.algorithm.AesAlgorithm;
import io.github.astrapi69.crypto.factories.SecretKeyFactoryExtensions;
import io.github.astrapi69.crypto.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypto.model.CryptModel;
import io.github.astrapi69.random.object.RandomStringFactory;

public class PrivateKeyWithSymmetricKeyDecryptorTest
{

	@Test public void testDecrypt() throws Exception
	{
		String actual;
		String expected;
		PrivateKey privateKey;
		PublicKey publicKey;
		SecretKey symmetricKey;
		CryptModel<Cipher, PublicKey, byte[]> encryptModel;
		CryptModel<Cipher, SecretKey, String> symmetricKeyModel;
		CryptModel<Cipher, PrivateKey, byte[]> decryptModel;
		byte[] testBytes;
		File derDir;
		File privatekeyDerFile;
		PublicKeyWithSymmetricKeyEncryptor encryptor;
		PrivateKeyWithSymmetricKeyDecryptor decryptor;
		byte[] decrypted;

		actual  = RandomStringFactory.newRandomLongString(10000000);

		testBytes = actual.getBytes("UTF-8");

		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		privatekeyDerFile = new File(derDir, "private.der");

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);
		publicKey = PrivateKeyExtensions.generatePublicKey(privateKey);

		decryptModel = CryptModel.<Cipher, PrivateKey, byte[]> builder().key(privateKey).build();
		encryptModel = CryptModel.<Cipher, PublicKey, byte[]> builder().key(publicKey).build();
		symmetricKey = SecretKeyFactoryExtensions
			.newSecretKey(AesAlgorithm.AES.getAlgorithm(), 128);
		symmetricKeyModel = CryptModel.<Cipher, SecretKey, String>builder().key(symmetricKey)
			.algorithm(AesAlgorithm.AES)
			.operationMode(Cipher.ENCRYPT_MODE)
			.build();

		encryptor = new PublicKeyWithSymmetricKeyEncryptor(encryptModel, symmetricKeyModel);
		assertNotNull(encryptor);

		byte[] encrypt = encryptor.encrypt(testBytes);

		decryptor = new PrivateKeyWithSymmetricKeyDecryptor(decryptModel);
		assertNotNull(decryptor);
		decrypted = decryptor.decrypt(encrypt);
		assertNotNull(decrypted);
		expected = new String(decrypted, "UTF-8");
		assertEquals(expected, actual);
	}
}
