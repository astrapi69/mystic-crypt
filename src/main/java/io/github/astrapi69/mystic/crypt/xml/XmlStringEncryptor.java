package io.github.astrapi69.mystic.crypt.xml;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.mystic.crypt.key.PublicKeyEncryptor;
import io.github.astrapi69.mystic.crypt.key.PublicKeyGenericEncryptor;
import org.apache.commons.codec.binary.Hex;

/**
 * The class {@link XmlStringEncryptor} can encrypt xml strings with his public key
 */
public class XmlStringEncryptor extends PublicKeyGenericEncryptor<String>
{

	/**
	 * Instantiates a new {@link XmlStringEncryptor} with the given {@link CryptModel} for the
	 * public key and the given {@link CryptModel} for the symmetric key
	 *
	 * @param model
	 *            The crypt model
	 * @param symmetricKeyModel
	 *            The symmetric key model
	 */
	public XmlStringEncryptor(CryptModel<Cipher, PublicKey, byte[]> model,
		CryptModel<Cipher, SecretKey, String> symmetricKeyModel)
	{
		super(model, symmetricKeyModel);
	}

	/**
	 * Instantiates a new {@link XmlStringEncryptor} with the given {@link PublicKey} object
	 *
	 * @param publicKey
	 *            the public key
	 */
	public XmlStringEncryptor(PublicKey publicKey)
	{
		super(publicKey);
	}

	/**
	 * Instantiates a new {@link XmlStringEncryptor} with the given {@link PublicKeyEncryptor}
	 * object
	 *
	 * @param encryptor
	 *            The encryptor that will do all the work
	 */
	public XmlStringEncryptor(PublicKeyEncryptor encryptor)
	{
		super(encryptor);
	}

}
