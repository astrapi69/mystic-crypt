/*
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
package io.github.astrapi69.mystic.crypt.gm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.URL;

import org.junit.jupiter.api.Test;
import org.meanbean.test.BeanTester;

import io.github.astrapi69.random.object.RandomWebObjectFactory;

/**
 * The class {@link GoogleMapsUrlSigner}
 */
public class GoogleMapsUrlSignerTest
{

	/**
	 * Test method for {@link GoogleMapsUrlSigner#convertToKeyByteArray(String)}
	 */
	@Test
	public void testConvertToKeyByteArray()
	{
		byte[] byteArray;

		byteArray = GoogleMapsUrlSigner.convertToKeyByteArray("YOUR_PRIVATE_KEY");
		assertNotNull(byteArray);
	}

	/**
	 * Test method for {@link GoogleMapsUrlSigner#signRequest(String, String, String)}
	 */
	@Test
	public void testSignRequestStringStringString() throws Exception
	{
		String signRequest;

		signRequest = GoogleMapsUrlSigner.signRequest("YOUR_PRIVATE_KEY", "/alpha/beta", "quest");
		assertNotNull(signRequest);
		// the returned value must be the signed resource, i.e. path?query with the signature
		// appended - guards against a mutant that returns an empty string
		assertTrue(signRequest.startsWith("/alpha/beta?quest&signature="),
			"expected the signed resource but was: " + signRequest);
		assertTrue(signRequest.length() > "/alpha/beta?quest&signature=".length(),
			"expected a non-empty signature to be appended");
	}

	/**
	 * Test method for {@link GoogleMapsUrlSigner#signRequest(URL, String)}
	 */
	@Test
	public void testSignRequestURLString() throws Exception
	{
		URL url;
		String signRequest;

		url = URI.create("https://maps.googleapis.com/maps/api/geocode/json?address=NewYork")
			.toURL();

		signRequest = GoogleMapsUrlSigner.signRequest(url, "YOUR_PRIVATE_KEY");
		assertNotNull(signRequest);
		// the returned value must be the full url (protocol://host + signed path) - guards against
		// a mutant that returns an empty string
		assertTrue(signRequest.startsWith("https://maps.googleapis.com"),
			"expected the full signed url but was: " + signRequest);
		assertTrue(signRequest.contains("&signature="),
			"expected the signature parameter to be appended");
	}

	/**
	 * Test method for {@link GoogleMapsUrlSigner#signRequest(URL, String)} using a random website
	 */
	@Test
	public void testSignRequestURLStringRandom() throws Exception
	{
		URL url = URI.create(RandomWebObjectFactory.randomWebsite()).toURL();
		String signRequest = GoogleMapsUrlSigner.signRequest(url, "YOUR_PRIVATE_KEY");
		assertNotNull(signRequest);
		// whatever host was generated, the result must be that url with a signature appended
		assertTrue(signRequest.startsWith(url.getProtocol() + "://" + url.getHost()),
			"expected the signed url to keep protocol and host but was: " + signRequest);
		assertTrue(signRequest.contains("signature="),
			"expected the signature parameter to be appended");
		assertTrue(signRequest.length() > url.toString().length(),
			"expected a non-empty signature to be appended");
	}

	/**
	 * Test method for {@link GoogleMapsUrlSigner} with {@link BeanTester}
	 */
	@Test
	public void testWithBeanTester()
	{
		final BeanTester beanTester = new BeanTester();
		beanTester.testBean(GoogleMapsUrlSigner.class);
	}


	/**
	 * A known answer, so that the signature itself is checked and not only where it stands. The
	 * expected value was computed with Python's hmac and base64 modules, independently of this
	 * library: HMAC-SHA1 under the key 00 01 .. 13, web-safe Base64 (#163)
	 */
	@Test
	public void testSignRequestGivesTheKnownSignature() throws Exception
	{
		String expected = "/maps/api/geocode/json?address=Lethe&client=gme-test&signature=DALziu772A3EL8LOvt-h69rudmk=";

		assertEquals(expected, GoogleMapsUrlSigner.signRequest("AAECAwQFBgcICQoLDA0ODxAREhM=",
			"/maps/api/geocode/json", "address=Lethe&client=gme-test"));
		assertEquals("https://maps.googleapis.com" + expected,
			GoogleMapsUrlSigner.signRequest(new java.net.URL(
				"https://maps.googleapis.com/maps/api/geocode/json?address=Lethe&client=gme-test"),
				"AAECAwQFBgcICQoLDA0ODxAREhM="));
	}
}
