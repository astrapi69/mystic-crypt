package de.alpharogroup.crypto.gm;

import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The class {@link GoogleMapsUrlSigner} can sign urls with the private key.
 * This class is inspired from this <a href=
 * "https://github.com/googlemaps/url-signing/blob/gh-pages/UrlSigner.java">class</a>
 */
public class GoogleMapsUrlSigner {

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
	public static String signRequest(URL url, String yourGooglePrivateKeyString)
			throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, URISyntaxException {

		// Retrieve the proper URL components to sign
		String resource = url.getPath() + '?' + url.getQuery();

		// Get an HMAC-SHA1 signing key from the raw key bytes
		SecretKeySpec sha1Key = new SecretKeySpec(convertToKeyByteArray(yourGooglePrivateKeyString), "HmacSHA1");

		// Get an HMAC-SHA1 Mac instance and initialize it with the HMAC-SHA1
		// key
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(sha1Key);

		// compute the binary signature for the request
		byte[] sigBytes = mac.doFinal(resource.getBytes());

		// base 64 encode the binary signature
		// Base64 is JDK 1.8 only - older versions may need to use Apache
		// Commons or similar.
		String signature = Base64.getEncoder().encodeToString(sigBytes);

		// convert the signature to 'web safe' base 64
		signature = signature.replace('+', '-');
		signature = signature.replace('/', '_');
		String signedRequestPath = resource + "&signature=" + signature;
		String urlGoogleMapSignedRequest = url.getProtocol() + "://" + url.getHost() + signedRequestPath;
		return urlGoogleMapSignedRequest;
	}

	/**
	 * Converts the given private key as String to an base 64 encoded byte
	 * array.
	 *
	 * @param yourGooglePrivateKeyString
	 *            the google private key as String
	 * @return the base 64 encoded byte array.
	 */
	public static byte[] convertToKeyByteArray(String yourGooglePrivateKeyString) {
		yourGooglePrivateKeyString = yourGooglePrivateKeyString.replace('-', '+');
		yourGooglePrivateKeyString = yourGooglePrivateKeyString.replace('_', '/');
		return Base64.getDecoder().decode(yourGooglePrivateKeyString);
	}

	/**
	 * Returns the context path with the signature as parameter.
	 *
	 * @param key
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
	public static String signRequest(String yourGooglePrivateKeyString, String path, String query)
			throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, URISyntaxException {

		// Retrieve the proper URL components to sign
		String resource = path + '?' + query;

		// Get an HMAC-SHA1 signing key from the raw key bytes
		SecretKeySpec sha1Key = new SecretKeySpec(convertToKeyByteArray(yourGooglePrivateKeyString), "HmacSHA1");

		// Get an HMAC-SHA1 Mac instance and initialize it with the HMAC-SHA1
		// key
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(sha1Key);

		// compute the binary signature for the request
		byte[] sigBytes = mac.doFinal(resource.getBytes());

		// base 64 encode the binary signature
		// Base64 is JDK 1.8 only - older versions may need to use Apache
		// Commons or similar.
		String signature = Base64.getEncoder().encodeToString(sigBytes);

		// convert the signature to 'web safe' base 64
		signature = signature.replace('+', '-');
		signature = signature.replace('/', '_');

		return resource + "&signature=" + signature;
	}

}
