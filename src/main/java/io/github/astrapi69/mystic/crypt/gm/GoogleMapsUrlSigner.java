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

import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import io.github.astrapi69.crypt.api.algorithm.MacAlgorithm;
import io.github.astrapi69.mystic.crypt.mac.HmacExtensions;


/**
 * The class {@link GoogleMapsUrlSigner} can sign urls with the private key. This class is inspired
 * from this
 * <a href= "https://github.com/googlemaps/url-signing/blob/gh-pages/UrlSigner.java">class</a>
 */
public final class GoogleMapsUrlSigner
{

	private GoogleMapsUrlSigner()
	{
	}

	/**
	 * Converts the given private key as String to an base 64 encoded byte array.
	 *
	 * @param yourGooglePrivateKeyString
	 *            the google private key as String
	 * @return the base 64 encoded byte array.
	 */
	public static byte[] convertToKeyByteArray(String yourGooglePrivateKeyString)
	{
		yourGooglePrivateKeyString = yourGooglePrivateKeyString.replace('-', '+');
		yourGooglePrivateKeyString = yourGooglePrivateKeyString.replace('_', '/');
		return Base64.getDecoder().decode(yourGooglePrivateKeyString);
	}

	/**
	 * Returns the context path with the signature as parameter.
	 *
	 * @param yourGooglePrivateKeyString
	 *            your private key from google as byte array in Base64 format
	 * @param path
	 *            the path
	 * @param query
	 *            the query
	 * @return the signed context path as string
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 * @throws InvalidKeyException
	 *             the invalid key exception
	 * @throws UnsupportedEncodingException
	 *             the unsupported encoding exception
	 * @throws URISyntaxException
	 *             the URI syntax exception
	 */
	public static String signRequest(final String yourGooglePrivateKeyString, final String path,
		final String query) throws NoSuchAlgorithmException, InvalidKeyException,
		UnsupportedEncodingException, URISyntaxException
	{

		// Retrieve the proper URL components to sign
		final String resource = path + '?' + query;

		final String signature = webSafeSignature(yourGooglePrivateKeyString, resource);

		return resource + "&signature=" + signature;
	}

	/**
	 * Returns the full url as String object with the signature as parameter.
	 *
	 * @param url
	 *            the url
	 * @param yourGooglePrivateKeyString
	 *            the your google private key string
	 * @return the string
	 * @throws NoSuchAlgorithmException
	 *             the no such algorithm exception
	 * @throws InvalidKeyException
	 *             the invalid key exception
	 * @throws UnsupportedEncodingException
	 *             the unsupported encoding exception
	 * @throws URISyntaxException
	 *             the URI syntax exception
	 */
	public static String signRequest(final URL url, final String yourGooglePrivateKeyString)
		throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException,
		URISyntaxException
	{

		// Retrieve the proper URL components to sign
		final String resource = url.getPath() + '?' + url.getQuery();

		final String signature = webSafeSignature(yourGooglePrivateKeyString, resource);
		final String signedRequestPath = resource + "&signature=" + signature;
		final String urlGoogleMapSignedRequest = url.getProtocol() + "://" + url.getHost()
			+ signedRequestPath;
		return urlGoogleMapSignedRequest;
	}


	/**
	 * The HMAC-SHA1 of the resource under the key, as web-safe Base64 - what both signing methods
	 * append. The HMAC itself comes from {@link HmacExtensions} (#163)
	 */
	private static String webSafeSignature(final String yourGooglePrivateKeyString,
		final String resource)
	{
		final byte[] sigBytes = HmacExtensions.hmac(MacAlgorithm.HmacSHA1,
			convertToKeyByteArray(yourGooglePrivateKeyString), resource.getBytes());
		return Base64.getEncoder().encodeToString(sigBytes).replace('+', '-').replace('/', '_');
	}
}
