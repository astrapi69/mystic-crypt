package io.github.astrapi69.crypto.simple;

import io.github.astrapi69.collections.array.ArrayFactory;
import io.github.astrapi69.random.object.RandomStringFactory;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;

import static org.testng.Assert.*;

/**
 * The unit test class for the class {@link OneTimePadEncryptor}
 */
public class OneTimePadEncryptorTest
{

	/**
	 * Test method for the {@link OneTimePadEncryptor#encrypt(byte[])} method
	 *
	 * @throws Exception
	 *             is thrown if a security error occurs
	 */
	@Test public void testEncrypt() throws Exception
	{
		byte[] actual;
		byte[] expected;
		OneTimePadEncryptor encryptor;
		String plainMessage;
		String theKey;
		byte[] key;
		plainMessage = "RandomStringFactory.newRandomLongString(10)";
		byte[] plainMessageBytes = plainMessage.getBytes(StandardCharsets.UTF_8);
		theKey = "topsecret";
		key = theKey.getBytes(StandardCharsets.UTF_8);
		encryptor = new OneTimePadEncryptor(key);

		actual = encryptor.encrypt(plainMessageBytes);
		expected = ArrayFactory.newByteArray(38, 14, 30, 23, 10, 14, 33, 17, 6, 26, 29, 20, 53, 18, 16, 7, 28, 1, 10, 93, 29, 22, 4, 33, 18, 29, 23, 28, 30, 63, 28, 29, 20, 32, 7, 1, 26, 29, 20, 91, 66, 67, 90);
		assertEquals(actual, expected);
	}
}
