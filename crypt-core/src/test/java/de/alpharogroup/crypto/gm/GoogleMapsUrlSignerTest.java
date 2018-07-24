/**
 * The MIT License
 *
 * Copyright (C) 2015 Asterios Raptis
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package de.alpharogroup.crypto.gm;

import static io.github.benas.randombeans.api.EnhancedRandom.random;
import static org.testng.Assert.assertNotNull;

import java.net.URL;

import org.testng.annotations.Test;

/**
 * The class {@link GoogleMapsUrlSigner}
 */
public class GoogleMapsUrlSignerTest
{

	/**
	 * Test method for {@link GoogleMapsUrlSigner#convertToKeyByteArray(String)}
	 */
	@Test
	public void testConvertToKeyByteArray() throws Exception
	{
		byte[] byteArray = GoogleMapsUrlSigner.convertToKeyByteArray("YOUR_PRIVATE_KEY");
		assertNotNull(byteArray);
	}

	/**
	 * Test method for {@link GoogleMapsUrlSigner#signRequest(String, String, String)}
	 */
	@Test
	public void testSignRequestStringStringString() throws Exception
	{
		String signRequest = GoogleMapsUrlSigner.signRequest("YOUR_PRIVATE_KEY", "/alpha/beta",
			"quest");
		assertNotNull(signRequest);
	}

	/**
	 * Test method for {@link GoogleMapsUrlSigner#signRequest(URL, String)}
	 */
	@Test
	public void testSignRequestURLString() throws Exception
	{
		final URL url = random(URL.class);
		String signRequest = GoogleMapsUrlSigner.signRequest(url, "YOUR_PRIVATE_KEY");
		assertNotNull(signRequest);
	}

}
