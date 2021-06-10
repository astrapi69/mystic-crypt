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
package de.alpharogroup.crypto.sign;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.io.File;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import org.testng.annotations.Test;

import io.github.astrapi69.crypto.compound.CompoundAlgorithm;
import io.github.astrapi69.crypto.key.reader.PrivateKeyReader;
import io.github.astrapi69.crypto.key.reader.PublicKeyReader;
import de.alpharogroup.file.search.PathFinder;

/**
 * The unit test class for the class {@link SignatureExtensions}
 */
public class SignatureExtensionsTest
{

	/**
	 * Test chained encrypt and decrypt with
	 * {@link SignatureExtensions#sign(PrivateKey, String, byte[])}
	 * {@link SignatureExtensions#verify(Certificate, String, byte[], byte[])}
	 *
	 * @throws Exception
	 *             is thrown if any security exception occured
	 */
	@Test
	public void testSignAndVerifyWithCertificate() throws Exception
	{
		String actual;
		String expected;
		String value;
		String signatureAlgorithm;
		Charset charset;
		Certificate certificate;
		File publickeyDerDir;
		File publickeyDerFile;
		File privatekeyDerFile;
		PrivateKey privateKey;
		PublicKey publicKey;

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "/der");
		publickeyDerFile = new File(publickeyDerDir, "public.der");
		privatekeyDerFile = new File(publickeyDerDir, "private.der");

		charset = StandardCharsets.UTF_8;
		value = new String(
			"Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)".getBytes(charset),
			charset);

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);
		signatureAlgorithm = CompoundAlgorithm.SHA256_WITH_RSA.getAlgorithm(); // SHA256withRSA
		byte[] signedWithMessageDigest = SignatureExtensions.sign(privateKey, signatureAlgorithm,
			value.getBytes(charset));

		actual = new String(signedWithMessageDigest, charset);

		expected = "O(��P�HN�ߐ\u0005�[�\u0002ƲN+�|�XjR�y�\u0018�t(L���U,����x���/�3��d�\u0003�\u0012,�H)�\f\u0007`<^�6Ip�U\u000B?\u0000��~i�.>7�m\u001E�;F�t\f�\u0012\u0003Q��w�q�_\u0004����\u0014\u0014\u0010*M\t���u�{&�\u0013_�7�\u0006qe�\u0004*���#X\u0007�n#��C��\u001C\u0002����|#�\"ny�2�R!��;��VV�\u0014�\u0014�����<f\u0016�\u07B4>8�m\u000E.\u000F�X�\u0383���b���E`gQ�\u0000��J�\u0006��K\u0007\u0014�6H�r�P\"����V>���lV0\u000B�b�=H\u000F";
		assertEquals(actual, expected);

		certificate = TestObjectFactory.newCertificateForTests(publicKey, privateKey,
			signatureAlgorithm);

		boolean verifed = SignatureExtensions.verify(certificate, signatureAlgorithm,
			value.getBytes(charset), signedWithMessageDigest);
		assertTrue(verifed);
	}

	/**
	 * Test chained encrypt and decrypt with
	 * {@link SignatureExtensions#sign(PrivateKey, String, byte[])}
	 * {@link SignatureExtensions#verify(PublicKey, String, byte[], byte[])}
	 *
	 * @throws Exception
	 *             is thrown if any security exception occured
	 */
	@Test
	public void testSignAndVerifyWithPublicKey() throws Exception
	{
		String actual;
		String expected;
		String value;
		String signatureAlgorithm;
		Charset charset;
		File publickeyDerDir;
		File publickeyDerFile;
		File privatekeyDerFile;
		PrivateKey privateKey;
		PublicKey publicKey;

		publickeyDerDir = new File(PathFinder.getSrcTestResourcesDir(), "/der");
		publickeyDerFile = new File(publickeyDerDir, "public.der");
		privatekeyDerFile = new File(publickeyDerDir, "private.der");

		charset = StandardCharsets.UTF_8;
		value = new String(
			"Lorem ipsum dolor sit amet, consetetur sadipscing elitr,;-)".getBytes(charset),
			charset);

		privateKey = PrivateKeyReader.readPrivateKey(privatekeyDerFile);

		publicKey = PublicKeyReader.readPublicKey(publickeyDerFile);
		signatureAlgorithm = CompoundAlgorithm.SHA256_WITH_RSA.getAlgorithm(); // SHA256withRSA
		byte[] signedWithMessageDigest = SignatureExtensions.sign(privateKey, signatureAlgorithm,
			value.getBytes(charset));

		actual = new String(signedWithMessageDigest, charset);

		expected = "O(��P�HN�ߐ\u0005�[�\u0002ƲN+�|�XjR�y�\u0018�t(L���U,����x���/�3��d�\u0003�\u0012,�H)�\f\u0007`<^�6Ip�U\u000B?\u0000��~i�.>7�m\u001E�;F�t\f�\u0012\u0003Q��w�q�_\u0004����\u0014\u0014\u0010*M\t���u�{&�\u0013_�7�\u0006qe�\u0004*���#X\u0007�n#��C��\u001C\u0002����|#�\"ny�2�R!��;��VV�\u0014�\u0014�����<f\u0016�\u07B4>8�m\u000E.\u000F�X�\u0383���b���E`gQ�\u0000��J�\u0006��K\u0007\u0014�6H�r�P\"����V>���lV0\u000B�b�=H\u000F";
		assertEquals(actual, expected);
		boolean verificationResult = SignatureExtensions.verify(publicKey, signatureAlgorithm,
			value.getBytes(charset), signedWithMessageDigest);
		assertTrue(verificationResult);
	}

}
