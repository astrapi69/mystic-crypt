package de.alpharogroup.crypto.key.writer;

import java.io.File;
import java.security.cert.X509Certificate;

import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.KeyFileFormat;
import de.alpharogroup.crypto.key.reader.CertificateReader;
import de.alpharogroup.file.search.PathFinder;

/**
 * The class {@link CertificateWriterTest}.
 */
public class CertificateWriterTest
{

	@Test
	public void test() throws Exception
	{
		final File pemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File certificatePemFile = new File(pemDir, "certificate.cert");
		final File derDir = new File(PathFinder.getSrcTestResourcesDir(), "der");
		final File certificateDerFile = new File(derDir, "certificate.der");

		X509Certificate certificate = CertificateReader.readPemCertificate(certificatePemFile);
		CertificateWriter.write(certificate, certificateDerFile, KeyFileFormat.DER);

	}

}
