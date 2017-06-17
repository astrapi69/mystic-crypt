package de.alpharogroup.crypto.key.reader;

import java.io.File;
import java.security.cert.X509Certificate;

import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import de.alpharogroup.file.search.PathFinder;

public class CertificateReaderTest {


	/**
	 * Test method for {@link CertificateReader#readPemCertificate(File)}.
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testReadPemCertificateFile() throws Exception
	{
		final File pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File certificateFile = new File(pemDir, "certificate.cert");

		X509Certificate certificate = CertificateReader.readPemCertificate(certificateFile);
		AssertJUnit.assertNotNull(certificate);
		System.out.println(certificate);
	}



	/**
	 * Test method for {@link CertificateReader#readCertificate(File)}.
	 *
	 * @throws Exception
	 *             the exception
	 */
	@Test
	public void testReadDerCertificateFile() throws Exception
	{
		final File derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		final File certificateDerFile = new File(derDir, "certificate.der");

		X509Certificate certificate = CertificateReader.readCertificate(certificateDerFile);
		AssertJUnit.assertNotNull(certificate);
		System.out.println(certificate);
	}

}
