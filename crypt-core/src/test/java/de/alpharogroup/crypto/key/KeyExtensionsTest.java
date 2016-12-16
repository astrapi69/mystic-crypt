package de.alpharogroup.crypto.key;

import java.io.File;
import java.security.PrivateKey;

import org.testng.annotations.Test;

import de.alpharogroup.file.search.PathFinder;

public class KeyExtensionsTest
{

	@Test
	public void testReadPemPrivateKey() throws Exception
	{
		final File privatekeyPemFile = new File(PathFinder.getSrcTestResourcesDir(), "private.pem");

		final PrivateKey privateKey = KeyExtensions.readPemPrivateKey(privatekeyPemFile);
	}

}
