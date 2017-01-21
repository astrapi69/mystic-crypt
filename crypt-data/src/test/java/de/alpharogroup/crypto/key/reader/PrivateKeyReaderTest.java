package de.alpharogroup.crypto.key.reader;

import java.io.File;
import java.security.PrivateKey;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.PrivateKeyExtensions;
import de.alpharogroup.crypto.provider.SecurityProvider;
import de.alpharogroup.file.search.PathFinder;

/**
 * Test class for {@link PrivateKeyReader}.
 */
public class PrivateKeyReaderTest
{

	/**
	 * Test method for {@link PrivateKeyReader#readPemPrivateKey(File, SecurityProvider)}.
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test(enabled = false)
	public void testReadPemPrivateKey() throws Exception
	{
		final File privatekeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File privatekeyPemFile = new File(privatekeyPemDir, "private.pem");

		Security.addProvider(new BouncyCastleProvider());
		final PrivateKey privateKey = PrivateKeyReader.readPemPrivateKey(privatekeyPemFile,
			SecurityProvider.BC);
		AssertJUnit.assertNotNull(privateKey);
	}

	/**
	 * Test method for {@link PrivateKeyReader#readPrivateKey(File)}.
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testReadPrivateKey() throws Exception
	{
		final File publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		final File privatekeyDerFile = new File(publickeyDerDir, "private.der");

		final PrivateKey privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		AssertJUnit.assertNotNull(privateKey);
	}


	/**
	 * Test method for {@link PrivateKeyReader#readPrivateKey(File)}.
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testReadPemFileAsBase64() throws Exception
	{
		final File privatekeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File privatekeyPemFile = new File(privatekeyPemDir, "private.pem");

		Security.addProvider(new BouncyCastleProvider());
		final String privateKeyAsBase64String = PrivateKeyReader
			.readPemFileAsBase64(privatekeyPemFile);

		final PrivateKey privateKey = PrivateKeyReader.readPemPrivateKey(privatekeyPemFile,
			SecurityProvider.BC);

		final String base64 = PrivateKeyExtensions.toBase64(privateKey);
		AssertJUnit.assertNotNull(privateKeyAsBase64String);
		AssertJUnit.assertNotNull(base64);
	}

}
