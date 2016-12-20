package de.alpharogroup.crypto.simple;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.CryptConst;

/**
 * Test class for the {@link SimpleEncryptor} and {@link SimpleDecryptor}.
 */
public class SimpleEnDecryptorTest
{

	@Test
	public void testEncrypt() throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException
	{
		final String test = "Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)";
		System.out.println("String before encryption:");
		System.out.println(test);

		final SimpleEncryptor encryptor = new SimpleEncryptor(CryptConst.PRIVATE_KEY);

		final String encrypted = encryptor.encrypt(test);
		System.out.println("String after encryption:");
		System.out.println(encrypted);
		final SimpleDecryptor decryptor = new SimpleDecryptor(CryptConst.PRIVATE_KEY);
		final String decryted = decryptor.decrypt(encrypted);
		System.out.println("String after decryption:");
		System.out.println(decryted);
		AssertJUnit.assertTrue("String before encryption is not equal after decryption.",
			test.equals(decryted));
	}

}
