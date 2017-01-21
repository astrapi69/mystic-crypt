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
package de.alpharogroup.crypto.key;

import java.io.File;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import de.alpharogroup.crypto.key.reader.PrivateKeyReader;
import de.alpharogroup.crypto.key.reader.PublicKeyReader;
import de.alpharogroup.crypto.provider.SecurityProvider;
import de.alpharogroup.file.search.PathFinder;

/**
 * Test class for the class {@link PrivateKeyExtensions}.
 */
public class PrivateKeyExtensionsTest
{

	/** The private key base64 encoded for use in tests. */
	public static String PRIVATE_KEY_BASE64_ENCODED =
		"-----BEGIN RSA PRIVATE KEY-----\n"
		+"MIIEogIBAAKCAQEA3prZMWp2kO6rfENO4p7XKNK9OGisJsx4KG1gGfScszdQfIxW" + "\n"
		+"/6KaAEWghUShd1n2tyX6Lo3UqA5t9OyhyUntXnAQ2CZPY5Nq2a5HCbH2e9QIzJdi" + "\n"
		+"PBNCXTs3wIprIGJv2T0O9qkOG7CIqhZjirnhaGUAAqMS0hvVDn+AApzv0FcJidaO" + "\n"
		+"5qX56Lso5lPpOWCRBEHqwQybXhFrDpbTbY0u0KhXogDnQ+jGt9lMEs8SGvKH0FuW" + "\n"
		+"3TuXsDNRk4uHS9w/jbbx1DC1sjFMv3jNHo4TrKopvRlcL2D3uHp/iAAIeU+DXeZS" + "\n"
		+"UIERi/FVkQxINRJf2bAdvRNDgTFtCUW4JQdmYQIDAQABAoIBABeq7xzJ7QFL3v+/" + "\n"
		+"SEvgB5BXl7a/qk4Vv1DNEEKyN1b2sqALa9SSPT16Ka8BtQkzj3+5kfgRLGMR5a78" + "\n"
		+"2dbE/W/lCmVw7U/xBJNQbE0jlsljqevWzKMGiS/QdAUMsocm8C1wyH6BSva2tlEf" + "\n"
		+"QEYnrUekNXQSUpX0T5rTA5FDjlvgMkiTptMT4sJ3jS3dMjXB713uo4nEHEeD+ND5" + "\n"
		+"QEKzulV0nguYu7EGqJkIUu/kVt8deFZ3QcDb3vPHeP4DpXLYTPzGkRekaD7XrOkc" + "\n"
		+"fWlzhk8zBnpffZ7Uxw/4thQXwssDpC9FYHxHH5we6S6bScUNqy6RAR5XlhE+49Ba" + "\n"
		+"JFPDXOECgYEA//NUHz0ImvoAgnNvP7DlCR/dPzVETnkScspf8w+3XVBNOWk8URu/" + "\n"
		+"CxbVMO9b+LXUiwt6tCuczl2WM+GKbcpk2mm47AO0OKCYOOUDj9l7OpslUXbkrHI/" + "\n"
		+"MnTIW/nfinaWURqJNEg6WzG/Hs8i6+wkvTDtVP+XOtadWDupavBMa4cCgYEA3qXe" + "\n"
		+"dB4zDZQeTOZQhr4d4KjNP/VPkraMVKsCOGVUmsoqyZD8wB9CXLSsqtrhEaBUFn0t" + "\n"
		+"ltwIA9McyzKRlB+s5M6gV5atSFarwA8EbiKmsivsGCY+YstyFjXj4dXr7CB3Y4ir" + "\n"
		+"mgDxVYj7pREauXGCWQZdsF6GKKwo6Qmk8naUKNcCgYBuihh6pVFiHTa7ID+bsjo4" + "\n"
		+"hpp3AfpOKdvd16k4wEDg/B1d/iUeom0PzPyl9boy39S7eGm2Bl/igGiuX2n5oL+N" + "\n"
		+"1LsYs0DSdAlKCR5QsgyWcwra9A4uq+i/UdB2aKQymKSywlMfUVJisElqdOsQGRyE" + "\n"
		+"2OynGPunXaj2wk2Y8c8PYQKBgFF+fPIbq6worv6OvqLTK7RzlMz4SWv2DV9gSKvD" + "\n"
		+"yzftD8Q/oYPg7TVpnFndS8xb1ut0Xh994iEkQMHPfKGvBmWpi98Dc+Gqd6sQ1BpL" + "\n"
		+"7KACm6QrO2KF/PhMOWEMIBKJv6la+RShi7Q3M4Szwghml8NmJRzNPGXevgquUQW+" + "\n"
		+"iXR5AoGAZ9hYXARnUY6Yv+1AdlQVBTVWPUZr3nS8ds8ItYS2boRwTKhvdJBVgdGT" + "\n"
		+"D7a5pWsHInK5dcO9csB5T08lHdmrAzgjRVtkNIvQ6EPVRVVsqILNXKVDMUpgO8CC" + "\n"
		+"6G0S1EXrNrxpcqjnWNL5EhmAKDRETTRuGB4h/RwjIa+owrx0kDo=\n"
		+"-----END RSA PRIVATE KEY-----\n";
	/**
	 * Test method for {@link PrivateKeyExtensions#generatePublicKey(PrivateKey)}
	 *
	 * @throws Exception
	 *             is thrown if an security error occurs
	 */
	@Test
	public void testGeneratePublicKey() throws Exception
	{

		final File keyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File publickeyPemFile = new File(keyPemDir, "public.pem");
		final File privatekeyPemFile = new File(keyPemDir, "private.pem");

		Security.addProvider(new BouncyCastleProvider());
		final PrivateKey privateKey = PrivateKeyReader.readPemPrivateKey(privatekeyPemFile,
			SecurityProvider.BC);

		final PublicKey expected = PublicKeyReader.readPemPublicKey(publickeyPemFile,
			SecurityProvider.BC);

		final PublicKey actual = PrivateKeyExtensions.generatePublicKey(privateKey);
		AssertJUnit.assertEquals(expected, actual);
	}

	/**
	 * Test method for {@link PrivateKeyExtensions#toBase64(PublicKey)}
	 *
	 * @throws Exception
	 *             is thrown if an security error occurs
	 *
	 */
	@Test(enabled = true)
	public void testToPemFormat() throws Exception
	{
		final File keyPemDir = new File(PathFinder.getSrcTestResourcesDir(), "pem");
		final File privatekeyPemFile = new File(keyPemDir, "private.pem");

		Security.addProvider(new BouncyCastleProvider());
		final PrivateKey privateKey = PrivateKeyReader.readPemPrivateKey(privatekeyPemFile,
			SecurityProvider.BC);

		final String actual = PrivateKeyExtensions.toPemFormat(privateKey);
		final String expected = PRIVATE_KEY_BASE64_ENCODED;
		AssertJUnit.assertEquals(expected, actual);

	}

}
