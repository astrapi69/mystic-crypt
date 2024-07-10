package io.github.astrapi69.mystic.crypt.ssl;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;

import org.junit.jupiter.api.Test;

import io.github.astrapi69.file.create.FileFactory;
import io.github.astrapi69.file.search.PathFinder;

/**
 * This class contains JUnit 5 tests for the KeystoreChecker class. It aims to cover all methods
 * under various scenarios to ensure high code coverage and correct functionality.
 */
class KeystoreVerifierTest
{

	/**
	 * Test to verify that a valid keystore file is correctly identified.
	 */
	@Test
	public void testValidKeystore() throws IOException
	{
		File keystoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"new-keystore.jks");
		String validKeystorePath = keystoreFile.getAbsolutePath();
		String password = "password";
		assertTrue(KeystoreVerifier.isKeystoreFile(validKeystorePath, password));
	}


	/**
	 * Test to verify that an invalid keystore file is correctly identified as invalid.
	 */
	@Test
	public void testInvalidKeystore()
	{
		String invalidKeystorePath = "path/to/invalid/keystore.jks";
		String password = "password";
		assertFalse(KeystoreVerifier.isKeystoreFile(invalidKeystorePath, password));
	}

	/**
	 * Test to verify that a valid keystore file of a specific type is recognized.
	 */
	@Test
	public void testValidKeystoreWithType() throws IOException
	{
		File keystoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"new-keystore.jks");
		String validKeystorePath = keystoreFile.getAbsolutePath();
		String password = "password";
		String type = "JKS";
		assertTrue(KeystoreVerifier.isKeystoreFile(validKeystorePath, password, type));
	}

	/**
	 * Test to verify that a valid keystore file of a specific types is recognized.
	 */
	@Test
	public void testValidKeystoreWithTypes() throws IOException
	{
		File keystoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"new-keystore.jks");
		String validKeystorePath = keystoreFile.getAbsolutePath();
		String password = "password";
		String[] types = { "JKS", "PKCS12" };
		assertTrue(KeystoreVerifier.isKeystoreFile(validKeystorePath, password, types));
	}

	/**
	 * Test to verify that an invalid keystore file or incorrect password is identified.
	 */
	@Test
	public void testInvalidKeystoreWithType()
	{
		String invalidKeystorePath = "path/to/invalid/keystore.jks";
		String password = "wrongpassword";
		String[] types = { "JKS", "PKCS12" };
		assertFalse(KeystoreVerifier.isKeystoreFile(invalidKeystorePath, password, types));
	}

	/**
	 * Test to verify that a File object representing a valid keystore is recognized.
	 */
	@Test
	public void testKeystoreFileObject() throws IOException
	{
		File keystoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"new-keystore.jks");
		String validKeystorePath = keystoreFile.getAbsolutePath();
		String password = "password";
		assertTrue(KeystoreVerifier.isKeystoreFile(keystoreFile, password));
	}

	/**
	 * Test to verify that a File object representing a valid keystore is recognized.
	 */
	@Test
	public void testKeystoreFileObjectWithTypes() throws IOException
	{
		File keystoreFile = FileFactory.newFile(PathFinder.getSrcTestResourcesDir(),
			"new-keystore.jks");
		String validKeystorePath = keystoreFile.getAbsolutePath();
		String[] types = { "JKS", "PKCS12" };
		String password = "password";
		assertTrue(KeystoreVerifier.isKeystoreFile(keystoreFile, password, types));
	}

}