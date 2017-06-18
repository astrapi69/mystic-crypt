/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
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
