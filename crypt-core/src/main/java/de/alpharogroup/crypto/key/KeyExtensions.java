package de.alpharogroup.crypto.key;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import de.alpharogroup.crypto.algorithm.Algorithm;

/**
 * The class {@link KeyExtensions}.
 */
public class KeyExtensions
{

	/** The Constant AES_KEY_LENGTH. */
	public static final int AES_KEY_LENGTH = 256;

	/** The Constant END_PUBLIC_KEY_SUFFIX. */
	public static final String END_PUBLIC_KEY_SUFFIX = "-----END PUBLIC KEY-----";

	/** The Constant BEGIN_PUBLIC_KEY_PREFIX. */
	public static final String BEGIN_PUBLIC_KEY_PREFIX = "-----BEGIN PUBLIC KEY-----\n";

	/** The Constant END_PRIVATE_KEY_SUFFIX. */
	public static final String END_PRIVATE_KEY_SUFFIX = "-----END PRIVATE KEY-----";

	/** The Constant BEGIN_PRIVATE_KEY_PREFIX. */
	public static final String BEGIN_PRIVATE_KEY_PREFIX = "-----BEGIN PRIVATE KEY-----";

	/** The Constant END_RSA_PRIVATE_KEY_SUFFIX. */
	public static final String END_RSA_PRIVATE_KEY_SUFFIX = "\n-----END RSA PRIVATE KEY-----";

	/** The Constant BEGIN_RSA_PRIVATE_KEY_PREFIX. */
	public static final String BEGIN_RSA_PRIVATE_KEY_PREFIX = "-----BEGIN RSA PRIVATE KEY-----\n";


	/**
	 * Gets the pem object.
	 *
	 * @param file the file
	 * @return the pem object
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public static PemObject getPemObject(final File file) throws IOException {
		PemObject pemObject;
		final PemReader pemReader = new PemReader(new InputStreamReader(new FileInputStream(file)));
		try {
			pemObject = pemReader.readPemObject();
		} finally {
			pemReader.close();
		}
		return pemObject;
	}

	/**
	 * Read public key.
	 *
	 * @param file the file
	 * @return the public key
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws InvalidKeySpecException the invalid key spec exception
	 * @throws NoSuchProviderException the no such provider exception
	 */
	public static PublicKey readPublicKey(final File file)
		throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		final byte[] keyBytes = Files.readAllBytes(file.toPath());
		return readPublicKey(keyBytes, "BC");
	}

	/**
	 * Read public key.
	 *
	 * @param publicKeyBytes the public key bytes
	 * @param provider the provider
	 * @return the public key
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws InvalidKeySpecException the invalid key spec exception
	 * @throws NoSuchProviderException the no such provider exception
	 */
	public static PublicKey readPublicKey(final byte[] publicKeyBytes, final String provider)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
		final KeyFactory keyFactory = KeyFactory.getInstance(Algorithm.RSA.getAlgorithm(), provider);
		return keyFactory.generatePublic(keySpec);
	}


	/**
	 * Read private key.
	 *
	 * @param file the file
	 * @return the private key
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws InvalidKeySpecException the invalid key spec exception
	 * @throws NoSuchProviderException the no such provider exception
	 */
	public static PrivateKey readPrivateKey(final File file)
		throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		final byte[] keyBytes = Files.readAllBytes(file.toPath());
		return readPrivateKey(keyBytes, "BC");
	}

	/**
	 * Read private key.
	 *
	 * @param privateKeyBytes the private key bytes
	 * @return the private key
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws InvalidKeySpecException the invalid key spec exception
	 * @throws NoSuchProviderException the no such provider exception
	 */
	public static PrivateKey readPrivateKey(final byte[] privateKeyBytes, final String provider)
		throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
	{
		final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		final KeyFactory keyFactory = KeyFactory.getInstance(Algorithm.RSA.getAlgorithm(), provider);
		return keyFactory.generatePrivate(keySpec);
	}

	/**
	 * Read pem private key.
	 *
	 * @param file the file
	 * @return the private key
	 * @throws Exception the exception
	 */
	public static PrivateKey readPemPrivateKey(final File file)
		throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		final byte[] keyBytes = Files.readAllBytes(file.toPath());

		final String privateKeyAsString = new String(keyBytes).replace(BEGIN_RSA_PRIVATE_KEY_PREFIX, "")
			.replace(END_RSA_PRIVATE_KEY_SUFFIX, "").trim();

		final byte[] decoded = new Base64().decode(privateKeyAsString);

		return readPrivateKey(decoded, "BC");
	}


	/**
	 * reads a public key from a file.
	 *
	 * @param f the f
	 * @return the read public key
	 * @throws Exception the exception
	 */
	public static PublicKey readPemPublicKey(final File file) throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());
		final byte[] keyBytes = Files.readAllBytes(file.toPath());

		final String publicKeyAsString = new String(keyBytes)
			.replace(BEGIN_PUBLIC_KEY_PREFIX, "")
			.replace(END_PUBLIC_KEY_SUFFIX, "");

		final byte[] decoded = Base64.decodeBase64(publicKeyAsString);

		return readPublicKey(decoded, "BC");
	}



}
