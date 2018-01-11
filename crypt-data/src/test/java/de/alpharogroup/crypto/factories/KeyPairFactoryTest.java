package de.alpharogroup.crypto.factories;

import java.io.File;
import java.security.PrivateKey;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.crypto.provider.SecurityProvider;
import de.alpharogroup.file.search.PathFinder;

public class KeyPairFactoryTest
{

	@Test
	public void testProtectPrivateKeyWithPassword() throws Exception
	{
		final File privatekeyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File privatekeyPemFile = new File(privatekeyPemDir, "private.pem");

		Security.addProvider(new BouncyCastleProvider());
		final String privateKeyAsBase64String = PrivateKeyReader
			.readPemFileAsBase64(privatekeyPemFile);

		final PrivateKey privateKey = PrivateKeyReader.readPemPrivateKey(privatekeyPemFile,
			SecurityProvider.BC);

		final byte[] pwprotectedKey = KeyPairFactory.protectPrivateKeyWithPassword(privateKey,
			"secret");


	}

}
