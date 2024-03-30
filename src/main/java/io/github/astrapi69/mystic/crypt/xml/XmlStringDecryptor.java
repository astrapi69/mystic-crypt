package io.github.astrapi69.mystic.crypt.xml;

import java.security.PrivateKey;

import javax.crypto.Cipher;

import io.github.astrapi69.crypt.data.model.CryptModel;
import io.github.astrapi69.mystic.crypt.key.PrivateKeyDecryptor;
import io.github.astrapi69.mystic.crypt.key.PrivateKeyGenericDecryptor;

/**
 * The class {@link XmlStringDecryptor} decrypts encrypted xml strings the was encrypted with the
 * public key of the pendant private key of this class
 */
public class XmlStringDecryptor extends PrivateKeyGenericDecryptor<String>
{

	/**
	 * Instantiates a new {@link XmlStringDecryptor} with the given {@link CryptModel}
	 *
	 * @param model
	 *            The crypt model
	 */
	public XmlStringDecryptor(CryptModel<Cipher, PrivateKey, byte[]> model)
	{
		super(model);
	}

	/**
	 * Instantiates a new {@link XmlStringDecryptor} with the given {@link PrivateKey}
	 *
	 * @param privateKey
	 *            The private key
	 */
	public XmlStringDecryptor(PrivateKey privateKey)
	{
		super(privateKey);
	}

	/**
	 * Instantiates a new {@link PrivateKeyGenericDecryptor} with the given
	 * {@link PrivateKeyDecryptor} object
	 *
	 * @param decryptor
	 *            The decryptor that will do the most work
	 */
	public XmlStringDecryptor(PrivateKeyDecryptor decryptor)
	{
		super(decryptor);
	}
}
