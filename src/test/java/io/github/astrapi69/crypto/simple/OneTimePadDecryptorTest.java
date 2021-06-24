package io.github.astrapi69.crypto.simple;

import static org.testng.Assert.assertEquals;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.testng.annotations.Test;

import io.github.astrapi69.collections.array.ArrayFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * The unit test class for the class {@link OneTimePadDecryptor}
 */
public class OneTimePadDecryptorTest
{

	/**
	 * Test method for the {@link OneTimePadDecryptor#decrypt(byte[])} method
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test
	public void testDecrypt() throws Exception
	{
		byte[] actual;
		byte[] expected;
		OneTimePadEncryptor encryptor;
		OneTimePadDecryptor decryptor;
		String plainMessage;
		String theKey;
		byte[] key;
		plainMessage = "RandomStringFactory.newRandomLongString(10)";
		byte[] plainMessageBytes = plainMessage.getBytes(StandardCharsets.UTF_8);
		theKey = "topsecret";
		key = theKey.getBytes(StandardCharsets.UTF_8);
		encryptor = new OneTimePadEncryptor(key);

		actual = encryptor.encrypt(plainMessageBytes);
		expected = ArrayFactory.newByteArray(38, 14, 30, 23, 10, 14, 33, 17, 6, 26, 29, 20, 53, 18,
			16, 7, 28, 1, 10, 93, 29, 22, 4, 33, 18, 29, 23, 28, 30, 63, 28, 29, 20, 32, 7, 1, 26,
			29, 20, 91, 66, 67, 90);
		assertEquals(actual, expected);
		decryptor = new OneTimePadDecryptor(key);
		actual = decryptor.decrypt(expected);
		expected = ArrayFactory.newByteArray(82, 97, 110, 100, 111, 109, 83, 116, 114, 105, 110,
			103, 70, 97, 99, 116, 111, 114, 121, 46, 110, 101, 119, 82, 97, 110, 100, 111, 109, 76,
			111, 110, 103, 83, 116, 114, 105, 110, 103, 40, 49, 48, 41);
		assertEquals(actual, expected);
	}
}
