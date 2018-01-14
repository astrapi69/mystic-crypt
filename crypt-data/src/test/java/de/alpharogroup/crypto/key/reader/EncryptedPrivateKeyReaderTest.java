package de.alpharogroup.crypto.key.reader;

import static org.testng.AssertJUnit.assertEquals;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.security.PrivateKey;

import org.meanbean.test.BeanTestException;
import org.meanbean.test.BeanTester;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.algorithm.KeyPairGeneratorAlgorithm;
import de.alpharogroup.crypto.key.writer.EncryptedPrivateKeyWriter;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link EncryptedPrivateKeyReader}.
 */
public class EncryptedPrivateKeyReaderTest
{
	PrivateKey expected;
	PrivateKey actual;

	File derDir;
	File encryptedPrivateKeyFile;
	PrivateKey readedPrivateKey;
	String password;

	/**
	 * Sets up method will be invoked before every unit test method in this class.
	 *
	 * @throws Exception
	 *             the exception
	 */
	@BeforeMethod
	protected void setUp() throws Exception
	{
		derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		encryptedPrivateKeyFile = new File(derDir, "encryptedPrivate.der");
	}

	/**
	 * Test method for
	 * {@link EncryptedPrivateKeyReader#decryptPasswordProtectedPrivateKey(File, String, String)}
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testDecryptPasswordProtectedPrivateKeyFilePasswordAlgorithm() throws Exception
	{
		readedPrivateKey = PrivateKeyReader
			.readPrivateKey(PathFinder.getSrcTestResourcesDir(), "der", "private.der");
		password = "secret";
		EncryptedPrivateKeyWriter.encryptPrivateKeyWithPassword(readedPrivateKey,
			encryptedPrivateKeyFile, password);


		final PrivateKey decryptedPrivateKey = EncryptedPrivateKeyReader
			.decryptPasswordProtectedPrivateKey(encryptedPrivateKeyFile, password,
				KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		expected = readedPrivateKey;
		actual = decryptedPrivateKey;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for
	 * {@link EncryptedPrivateKeyReader#decryptPasswordProtectedPrivateKey(File, String)}
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testDecryptPasswordProtectedPrivateKeyFilePassword() throws Exception
	{
		readedPrivateKey = PrivateKeyReader
			.readPrivateKey(PathFinder.getSrcTestResourcesDir(), "der", "private.der");
		password = "secret";
		EncryptedPrivateKeyWriter.encryptPrivateKeyWithPassword(readedPrivateKey,
			encryptedPrivateKeyFile, password);


		final PrivateKey decryptedPrivateKey = EncryptedPrivateKeyReader
			.decryptPasswordProtectedPrivateKey(encryptedPrivateKeyFile, password);
		expected = readedPrivateKey;
		actual = decryptedPrivateKey;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link EncryptedPrivateKeyReader#decryptPasswordProtectedPrivateKey(byte[], String, String)}
	 *
	 * @throws Exception
	 *             is thrown if any error occurs on the execution
	 */
	@Test
	public void testDecryptPasswordProtectedPrivateKeyByteArray() throws Exception
	{
		readedPrivateKey = PrivateKeyReader
			.readPrivateKey(PathFinder.getSrcTestResourcesDir(), "der", "private.der");
		password = "secret";
		final byte[] pwprotectedKey = EncryptedPrivateKeyWriter.encryptPrivateKeyWithPassword(readedPrivateKey,
			password);

		final PrivateKey decryptedPrivateKey = EncryptedPrivateKeyReader.decryptPasswordProtectedPrivateKey(
			pwprotectedKey, password, KeyPairGeneratorAlgorithm.RSA.getAlgorithm());
		expected = readedPrivateKey;
		actual = decryptedPrivateKey;
		assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link EncryptedPrivateKeyReader} with {@link BeanTester}
	 */
	@Test(expectedExceptions = { BeanTestException.class, InvocationTargetException.class,
			UnsupportedOperationException.class })
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(EncryptedPrivateKeyReader.class);
	}

}
